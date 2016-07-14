/*
 * Copyright (c) 1998-2015 Apple Inc. All rights reserved.
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
#include <sys/syslog.h>
#include <sys/uio.h>
#include <sys/uio_internal.h>
#include <sys/ev.h>
#include <sys/kdebug.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/priv.h>
#include <sys/kern_event.h>
#include <net/route.h>
#include <net/init.h>
#include <net/ntstat.h>
#include <net/content_filter.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/flow_divert.h>
#include <kern/zalloc.h>
#include <kern/locks.h>
#include <machine/limits.h>
#include <libkern/OSAtomic.h>
#include <pexpert/pexpert.h>
#include <kern/assert.h>
#include <kern/task.h>
#include <sys/kpi_mbuf.h>
#include <sys/mcache.h>
#include <sys/unpcb.h>

#if CONFIG_MACF
#include <security/mac.h>
#include <security/mac_framework.h>
#endif /* MAC */

#if MULTIPATH
#include <netinet/mp_pcb.h>
#include <netinet/mptcp_var.h>
#endif /* MULTIPATH */

#define ROUNDUP(a, b) (((a) + ((b) - 1)) & (~((b) - 1)))

#if DEBUG || DEVELOPMENT
#define	DEBUG_KERNEL_ADDRPERM(_v) (_v)
#else
#define	DEBUG_KERNEL_ADDRPERM(_v) VM_KERNEL_ADDRPERM(_v)
#endif

/* TODO: this should be in a header file somewhere */
extern char *proc_name_address(void *p);

static u_int32_t	so_cache_hw;	/* High water mark for socache */
static u_int32_t	so_cache_timeouts;	/* number of timeouts */
static u_int32_t	so_cache_max_freed;	/* max freed per timeout */
static u_int32_t	cached_sock_count = 0;
STAILQ_HEAD(, socket)	so_cache_head;
int	max_cached_sock_count = MAX_CACHED_SOCKETS;
static u_int32_t	so_cache_time;
static int		socketinit_done;
static struct zone	*so_cache_zone;

static lck_grp_t	*so_cache_mtx_grp;
static lck_attr_t	*so_cache_mtx_attr;
static lck_grp_attr_t	*so_cache_mtx_grp_attr;
static lck_mtx_t	*so_cache_mtx;

#include <machine/limits.h>

static void	filt_sordetach(struct knote *kn);
static int	filt_soread(struct knote *kn, long hint);
static void	filt_sowdetach(struct knote *kn);
static int	filt_sowrite(struct knote *kn, long hint);
static void	filt_sockdetach(struct knote *kn);
static int	filt_sockev(struct knote *kn, long hint);
static void	filt_socktouch(struct knote *kn, struct kevent_internal_s *kev,
    long type);

static int sooptcopyin_timeval(struct sockopt *, struct timeval *);
static int sooptcopyout_timeval(struct sockopt *, const struct timeval *);

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
	.f_touch = filt_socktouch,
};

SYSCTL_DECL(_kern_ipc);

#define	EVEN_MORE_LOCKING_DEBUG 0

int socket_debug = 0;
SYSCTL_INT(_kern_ipc, OID_AUTO, socket_debug,
	CTLFLAG_RW | CTLFLAG_LOCKED, &socket_debug, 0, "");

static int socket_zone = M_SOCKET;
so_gen_t	so_gencnt;	/* generation count for sockets */

MALLOC_DEFINE(M_SONAME, "soname", "socket name");
MALLOC_DEFINE(M_PCB, "pcb", "protocol control block");

#define	DBG_LAYER_IN_BEG	NETDBG_CODE(DBG_NETSOCK, 0)
#define	DBG_LAYER_IN_END	NETDBG_CODE(DBG_NETSOCK, 2)
#define	DBG_LAYER_OUT_BEG	NETDBG_CODE(DBG_NETSOCK, 1)
#define	DBG_LAYER_OUT_END	NETDBG_CODE(DBG_NETSOCK, 3)
#define	DBG_FNC_SOSEND		NETDBG_CODE(DBG_NETSOCK, (4 << 8) | 1)
#define	DBG_FNC_SOSEND_LIST	NETDBG_CODE(DBG_NETSOCK, (4 << 8) | 3)
#define	DBG_FNC_SORECEIVE	NETDBG_CODE(DBG_NETSOCK, (8 << 8))
#define	DBG_FNC_SORECEIVE_LIST	NETDBG_CODE(DBG_NETSOCK, (8 << 8) | 3)
#define	DBG_FNC_SOSHUTDOWN	NETDBG_CODE(DBG_NETSOCK, (9 << 8))

#define	MAX_SOOPTGETM_SIZE	(128 * MCLBYTES)

int somaxconn = SOMAXCONN;
SYSCTL_INT(_kern_ipc, KIPC_SOMAXCONN, somaxconn,
	CTLFLAG_RW | CTLFLAG_LOCKED, &somaxconn, 0, "");

/* Should we get a maximum also ??? */
static int sosendmaxchain = 65536;
static int sosendminchain = 16384;
static int sorecvmincopy  = 16384;
SYSCTL_INT(_kern_ipc, OID_AUTO, sosendminchain,
	CTLFLAG_RW | CTLFLAG_LOCKED, &sosendminchain, 0, "");
SYSCTL_INT(_kern_ipc, OID_AUTO, sorecvmincopy,
	CTLFLAG_RW | CTLFLAG_LOCKED, &sorecvmincopy, 0, "");

/*
 * Set to enable jumbo clusters (if available) for large writes when
 * the socket is marked with SOF_MULTIPAGES; see below.
 */
int sosendjcl = 1;
SYSCTL_INT(_kern_ipc, OID_AUTO, sosendjcl,
	CTLFLAG_RW | CTLFLAG_LOCKED, &sosendjcl, 0, "");

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
SYSCTL_INT(_kern_ipc, OID_AUTO, sosendjcl_ignore_capab,
	CTLFLAG_RW | CTLFLAG_LOCKED, &sosendjcl_ignore_capab, 0, "");

/*
 * Set this to ignore SOF1_IF_2KCL and use big clusters for large
 * writes on the socket for all protocols on any network interfaces.
 * Be extra careful when setting this to 1, because sending down packets with
 * clusters larger that 2 KB might lead to system panics or data corruption.
 * When set to 0, the system will respect SOF1_IF_2KCL, which is set
 * on the outgoing interface
 * Set this to 1  for testing/debugging purposes only.
 */
int sosendbigcl_ignore_capab = 0;
SYSCTL_INT(_kern_ipc, OID_AUTO, sosendbigcl_ignore_capab,
	CTLFLAG_RW | CTLFLAG_LOCKED, &sosendbigcl_ignore_capab, 0, "");

int sodefunctlog = 0;
SYSCTL_INT(_kern_ipc, OID_AUTO, sodefunctlog, CTLFLAG_RW | CTLFLAG_LOCKED,
	&sodefunctlog, 0, "");

int sothrottlelog = 0;
SYSCTL_INT(_kern_ipc, OID_AUTO, sothrottlelog, CTLFLAG_RW | CTLFLAG_LOCKED,
	&sothrottlelog, 0, "");

int sorestrictrecv = 1;
SYSCTL_INT(_kern_ipc, OID_AUTO, sorestrictrecv, CTLFLAG_RW | CTLFLAG_LOCKED,
	&sorestrictrecv, 0, "Enable inbound interface restrictions");

int sorestrictsend = 1;
SYSCTL_INT(_kern_ipc, OID_AUTO, sorestrictsend, CTLFLAG_RW | CTLFLAG_LOCKED,
	&sorestrictsend, 0, "Enable outbound interface restrictions");

int soreserveheadroom = 1;
SYSCTL_INT(_kern_ipc, OID_AUTO, soreserveheadroom, CTLFLAG_RW | CTLFLAG_LOCKED,
	&soreserveheadroom, 0, "To allocate contiguous datagram buffers");

extern struct inpcbinfo tcbinfo;

/* TODO: these should be in header file */
extern int get_inpcb_str_size(void);
extern int get_tcp_str_size(void);

static unsigned int sl_zone_size;		/* size of sockaddr_list */
static struct zone *sl_zone;			/* zone for sockaddr_list */

static unsigned int se_zone_size;		/* size of sockaddr_entry */
static struct zone *se_zone;			/* zone for sockaddr_entry */

vm_size_t	so_cache_zone_element_size;

static int sodelayed_copy(struct socket *, struct uio *, struct mbuf **,
    user_ssize_t *);
static void cached_sock_alloc(struct socket **, int);
static void cached_sock_free(struct socket *);

/*
 * Maximum of extended background idle sockets per process
 * Set to zero to disable further setting of the option
 */

#define	SO_IDLE_BK_IDLE_MAX_PER_PROC	1
#define	SO_IDLE_BK_IDLE_TIME		600
#define	SO_IDLE_BK_IDLE_RCV_HIWAT	131072

struct soextbkidlestat soextbkidlestat;

SYSCTL_UINT(_kern_ipc, OID_AUTO, maxextbkidleperproc,
	CTLFLAG_RW | CTLFLAG_LOCKED, &soextbkidlestat.so_xbkidle_maxperproc, 0,
	"Maximum of extended background idle sockets per process");

SYSCTL_UINT(_kern_ipc, OID_AUTO, extbkidletime, CTLFLAG_RW | CTLFLAG_LOCKED,
	&soextbkidlestat.so_xbkidle_time, 0,
	"Time in seconds to keep extended background idle sockets");

SYSCTL_UINT(_kern_ipc, OID_AUTO, extbkidlercvhiwat, CTLFLAG_RW | CTLFLAG_LOCKED,
	&soextbkidlestat.so_xbkidle_rcvhiwat, 0,
	"High water mark for extended background idle sockets");

SYSCTL_STRUCT(_kern_ipc, OID_AUTO, extbkidlestat, CTLFLAG_RD | CTLFLAG_LOCKED,
	&soextbkidlestat, soextbkidlestat, "");

int so_set_extended_bk_idle(struct socket *, int);

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
	_CASSERT(sizeof(so_gencnt) == sizeof(uint64_t));
	VERIFY(IS_P2ALIGNED(&so_gencnt, sizeof(uint32_t)));

#ifdef __LP64__
	_CASSERT(sizeof(struct sa_endpoints) == sizeof(struct user64_sa_endpoints));
	_CASSERT(offsetof(struct sa_endpoints, sae_srcif) == offsetof(struct user64_sa_endpoints, sae_srcif));
	_CASSERT(offsetof(struct sa_endpoints, sae_srcaddr) == offsetof(struct user64_sa_endpoints, sae_srcaddr));
	_CASSERT(offsetof(struct sa_endpoints, sae_srcaddrlen) == offsetof(struct user64_sa_endpoints, sae_srcaddrlen));
	_CASSERT(offsetof(struct sa_endpoints, sae_dstaddr) == offsetof(struct user64_sa_endpoints, sae_dstaddr));
	_CASSERT(offsetof(struct sa_endpoints, sae_dstaddrlen) == offsetof(struct user64_sa_endpoints, sae_dstaddrlen));
#else
	_CASSERT(sizeof(struct sa_endpoints) == sizeof(struct user32_sa_endpoints));
	_CASSERT(offsetof(struct sa_endpoints, sae_srcif) == offsetof(struct user32_sa_endpoints, sae_srcif));
	_CASSERT(offsetof(struct sa_endpoints, sae_srcaddr) == offsetof(struct user32_sa_endpoints, sae_srcaddr));
	_CASSERT(offsetof(struct sa_endpoints, sae_srcaddrlen) == offsetof(struct user32_sa_endpoints, sae_srcaddrlen));
	_CASSERT(offsetof(struct sa_endpoints, sae_dstaddr) == offsetof(struct user32_sa_endpoints, sae_dstaddr));
	_CASSERT(offsetof(struct sa_endpoints, sae_dstaddrlen) == offsetof(struct user32_sa_endpoints, sae_dstaddrlen));
#endif

	if (socketinit_done) {
		printf("socketinit: already called...\n");
		return;
	}
	socketinit_done = 1;

	PE_parse_boot_argn("socket_debug", &socket_debug,
	    sizeof (socket_debug));

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

	/* cached sockets mutex */
	so_cache_mtx = lck_mtx_alloc_init(so_cache_mtx_grp, so_cache_mtx_attr);
	if (so_cache_mtx == NULL) {
		panic("%s: unable to allocate so_cache_mtx\n", __func__);
		/* NOTREACHED */
	}
	STAILQ_INIT(&so_cache_head);

	so_cache_zone_element_size = (vm_size_t)(sizeof (struct socket) + 4
	    + get_inpcb_str_size() + 4 + get_tcp_str_size());

	so_cache_zone = zinit(so_cache_zone_element_size,
	    (120000 * so_cache_zone_element_size), 8192, "socache zone");
	zone_change(so_cache_zone, Z_CALLERACCT, FALSE);
	zone_change(so_cache_zone, Z_NOENCRYPT, TRUE);

	sl_zone_size = sizeof (struct sockaddr_list);
	if ((sl_zone = zinit(sl_zone_size, 1024 * sl_zone_size, 1024,
	    "sockaddr_list")) == NULL) {
		panic("%s: unable to allocate sockaddr_list zone\n", __func__);
		/* NOTREACHED */
	}
	zone_change(sl_zone, Z_CALLERACCT, FALSE);
	zone_change(sl_zone, Z_EXPAND, TRUE);

	se_zone_size = sizeof (struct sockaddr_entry);
	if ((se_zone = zinit(se_zone_size, 1024 * se_zone_size, 1024,
	    "sockaddr_entry")) == NULL) {
		panic("%s: unable to allocate sockaddr_entry zone\n", __func__);
		/* NOTREACHED */
	}
	zone_change(se_zone, Z_CALLERACCT, FALSE);
	zone_change(se_zone, Z_EXPAND, TRUE);

	bzero(&soextbkidlestat, sizeof(struct soextbkidlestat));
	soextbkidlestat.so_xbkidle_maxperproc = SO_IDLE_BK_IDLE_MAX_PER_PROC;
	soextbkidlestat.so_xbkidle_time = SO_IDLE_BK_IDLE_TIME;
	soextbkidlestat.so_xbkidle_rcvhiwat = SO_IDLE_BK_IDLE_RCV_HIWAT;

	in_pcbinit();
	sflt_init();
	socket_tclass_init();
#if MULTIPATH
	mp_pcbinit();
#endif /* MULTIPATH */
}

static void
cached_sock_alloc(struct socket **so, int waitok)
{
	caddr_t	temp;
	uintptr_t offset;

	lck_mtx_lock(so_cache_mtx);

	if (!STAILQ_EMPTY(&so_cache_head)) {
		VERIFY(cached_sock_count > 0);

		*so = STAILQ_FIRST(&so_cache_head);
		STAILQ_REMOVE_HEAD(&so_cache_head, so_cache_ent);
		STAILQ_NEXT((*so), so_cache_ent) = NULL;

		cached_sock_count--;
		lck_mtx_unlock(so_cache_mtx);

		temp = (*so)->so_saved_pcb;
		bzero((caddr_t)*so, sizeof (struct socket));

		(*so)->so_saved_pcb = temp;
	} else {

		lck_mtx_unlock(so_cache_mtx);

		if (waitok)
			*so = (struct socket *)zalloc(so_cache_zone);
		else
			*so = (struct socket *)zalloc_noblock(so_cache_zone);

		if (*so == NULL)
			return;

		bzero((caddr_t)*so, sizeof (struct socket));

		/*
		 * Define offsets for extra structures into our
		 * single block of memory. Align extra structures
		 * on longword boundaries.
		 */

		offset = (uintptr_t)*so;
		offset += sizeof (struct socket);

		offset = ALIGN(offset);

		(*so)->so_saved_pcb = (caddr_t)offset;
		offset += get_inpcb_str_size();

		offset = ALIGN(offset);

		((struct inpcb *)(void *)(*so)->so_saved_pcb)->inp_saved_ppcb =
		    (caddr_t)offset;
	}

	OSBitOrAtomic(SOF1_CACHED_IN_SOCK_LAYER, &(*so)->so_flags1);
}

static void
cached_sock_free(struct socket *so)
{

	lck_mtx_lock(so_cache_mtx);

	so_cache_time = net_uptime();
	if (++cached_sock_count > max_cached_sock_count) {
		--cached_sock_count;
		lck_mtx_unlock(so_cache_mtx);
		zfree(so_cache_zone, so);
	} else {
		if (so_cache_hw < cached_sock_count)
			so_cache_hw = cached_sock_count;

		STAILQ_INSERT_TAIL(&so_cache_head, so, so_cache_ent);

		so->cache_timestamp = so_cache_time;
		lck_mtx_unlock(so_cache_mtx);
	}
}

void
so_update_last_owner_locked(struct socket *so, proc_t self)
{
	if (so->last_pid != 0) {
		/*
		 * last_pid and last_upid should remain zero for sockets
		 * created using sock_socket. The check above achieves that
		 */
		if (self == PROC_NULL)
			self = current_proc();

		if (so->last_upid != proc_uniqueid(self) ||
		    so->last_pid != proc_pid(self)) {
			so->last_upid = proc_uniqueid(self);
			so->last_pid = proc_pid(self);
			proc_getexecutableuuid(self, so->last_uuid,
			    sizeof (so->last_uuid));
		}
		proc_pidoriginatoruuid(so->so_vuuid, sizeof(so->so_vuuid));
	}
}

void
so_update_policy(struct socket *so)
{
	if (SOCK_DOM(so) == PF_INET || SOCK_DOM(so) == PF_INET6)
		(void) inp_update_policy(sotoinpcb(so));
}

#if NECP
static void
so_update_necp_policy(struct socket *so, struct sockaddr *override_local_addr,
    struct sockaddr *override_remote_addr)
{
	if (SOCK_DOM(so) == PF_INET || SOCK_DOM(so) == PF_INET6)
		inp_update_necp_policy(sotoinpcb(so), override_local_addr,
		    override_remote_addr, 0);
}
#endif /* NECP */

boolean_t
so_cache_timer(void)
{
	struct socket	*p;
	int		n_freed = 0;
	boolean_t rc = FALSE;

	lck_mtx_lock(so_cache_mtx);
	so_cache_timeouts++;
	so_cache_time = net_uptime();

	while (!STAILQ_EMPTY(&so_cache_head)) {
		VERIFY(cached_sock_count > 0);
		p = STAILQ_FIRST(&so_cache_head);
		if ((so_cache_time - p->cache_timestamp) <
			SO_CACHE_TIME_LIMIT)
			break;

		STAILQ_REMOVE_HEAD(&so_cache_head, so_cache_ent);
		--cached_sock_count;

		zfree(so_cache_zone, p);

		if (++n_freed >= SO_CACHE_MAX_FREE_BATCH) {
			so_cache_max_freed++;
			break;
		}
	}

	/* Schedule again if there is more to cleanup */
	if (!STAILQ_EMPTY(&so_cache_head))
		rc = TRUE;

	lck_mtx_unlock(so_cache_mtx);
	return (rc);
}

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
	if (so != NULL) {
		so->so_gencnt = OSIncrementAtomic64((SInt64 *)&so_gencnt);
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

int
socreate_internal(int dom, struct socket **aso, int type, int proto,
    struct proc *p, uint32_t flags, struct proc *ep)
{
	struct protosw *prp;
	struct socket *so;
	int error = 0;

#if TCPDEBUG
	extern int tcpconsdebug;
#endif

	VERIFY(aso != NULL);
	*aso = NULL;

	if (proto != 0)
		prp = pffindproto(dom, proto, type);
	else
		prp = pffindtype(dom, type);

	if (prp == NULL || prp->pr_usrreqs->pru_attach == NULL) {
		if (pffinddomain(dom) == NULL)
			return (EAFNOSUPPORT);
		if (proto != 0) {
			if (pffindprotonotype(dom, proto) != NULL)
				return (EPROTOTYPE);
		}
		return (EPROTONOSUPPORT);
	}
	if (prp->pr_type != type)
		return (EPROTOTYPE);
	so = soalloc(1, dom, type);
	if (so == NULL)
		return (ENOBUFS);

	if (flags & SOCF_ASYNC)
		so->so_state |= SS_NBIO;
#if MULTIPATH
	if (flags & SOCF_MP_SUBFLOW) {
		/*
		 * A multipath subflow socket is used internally in the kernel,
		 * therefore it does not have a file desciptor associated by
		 * default.
		 */
		so->so_state |= SS_NOFDREF;
		so->so_flags |= SOF_MP_SUBFLOW;
	}
#endif /* MULTIPATH */

	TAILQ_INIT(&so->so_incomp);
	TAILQ_INIT(&so->so_comp);
	so->so_type = type;
	so->last_upid = proc_uniqueid(p);
	so->last_pid = proc_pid(p);
	proc_getexecutableuuid(p, so->last_uuid, sizeof (so->last_uuid));
	proc_pidoriginatoruuid(so->so_vuuid, sizeof(so->so_vuuid));

	if (ep != PROC_NULL && ep != p) {
		so->e_upid = proc_uniqueid(ep);
		so->e_pid = proc_pid(ep);
		proc_getexecutableuuid(ep, so->e_uuid, sizeof (so->e_uuid));
		so->so_flags |= SOF_DELEGATED;
	}

	so->so_cred = kauth_cred_proc_ref(p);
	if (!suser(kauth_cred_get(), NULL))
		so->so_state |= SS_PRIV;

	so->so_proto = prp;
	so->so_rcv.sb_flags |= SB_RECV;
	so->so_rcv.sb_so = so->so_snd.sb_so = so;
	so->next_lock_lr = 0;
	so->next_unlock_lr = 0;

#if CONFIG_MACF_SOCKET
	mac_socket_label_associate(kauth_cred_get(), so);
#endif /* MAC_SOCKET */

	/*
	 * Attachment will create the per pcb lock if necessary and
	 * increase refcount for creation, make sure it's done before
	 * socket is inserted in lists.
	 */
	so->so_usecount++;

	error = (*prp->pr_usrreqs->pru_attach)(so, proto, p);
	if (error != 0) {
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

	atomic_add_32(&prp->pr_domain->dom_refs, 1);
	TAILQ_INIT(&so->so_evlist);

	/* Attach socket filters for this protocol */
	sflt_initsock(so);
#if TCPDEBUG
	if (tcpconsdebug == 2)
		so->so_options |= SO_DEBUG;
#endif
	so_set_default_traffic_class(so);

	/*
	 * If this thread or task is marked to create backgrounded sockets,
	 * mark the socket as background.
	 */
	if (proc_get_effective_thread_policy(current_thread(),
	    TASK_POLICY_NEW_SOCKETS_BG)) {
		socket_set_traffic_mgt_flags(so, TRAFFIC_MGT_SO_BACKGROUND);
		so->so_background_thread = current_thread();
	}

	switch (dom) {
	/*
	 * Don't mark Unix domain, system or multipath sockets as
	 * eligible for defunct by default.
	 */
	case PF_LOCAL:
	case PF_SYSTEM:
	case PF_MULTIPATH:
		so->so_flags |= SOF_NODEFUNCT;
		break;
	default:
		break;
	}

	/*
	 * Entitlements can't be checked at socket creation time except if the
	 * application requested a feature guarded by a privilege (c.f., socket
	 * delegation).
	 * The priv(9) and the Sandboxing APIs are designed with the idea that
	 * a privilege check should only be triggered by a userland request.
	 * A privilege check at socket creation time is time consuming and
	 * could trigger many authorisation error messages from the security
	 * APIs.
	 */

	*aso = so;

	return (0);
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
 *	<pru_attach>:???		[other protocol families, IPSEC]
 */
int
socreate(int dom, struct socket **aso, int type, int proto)
{
	return (socreate_internal(dom, aso, type, proto, current_proc(), 0,
	    PROC_NULL));
}

int
socreate_delegate(int dom, struct socket **aso, int type, int proto, pid_t epid)
{
	int error = 0;
	struct proc *ep = PROC_NULL;

	if ((proc_selfpid() != epid) && ((ep = proc_find(epid)) == PROC_NULL)) {
		error = ESRCH;
		goto done;
	}

	error = socreate_internal(dom, aso, type, proto, current_proc(), 0, ep);

	/*
	 * It might not be wise to hold the proc reference when calling
	 * socreate_internal since it calls soalloc with M_WAITOK
	 */
done:
	if (ep != PROC_NULL)
		proc_rele(ep);

	return (error);
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
sobindlock(struct socket *so, struct sockaddr *nam, int dolock)
{
	struct proc *p = current_proc();
	int error = 0;

	if (dolock)
		socket_lock(so, 1);
	VERIFY(so->so_usecount > 1);

	so_update_last_owner_locked(so, p);
	so_update_policy(so);

#if NECP
	so_update_necp_policy(so, nam, NULL);
#endif /* NECP */

	/*
	 * If this is a bind request on a socket that has been marked
	 * as inactive, reject it now before we go any further.
	 */
	if (so->so_flags & SOF_DEFUNCT) {
		error = EINVAL;
		SODEFUNCTLOG(("%s[%d]: defunct so 0x%llx [%d,%d] (%d)\n",
		    __func__, proc_pid(p), (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
		    SOCK_DOM(so), SOCK_TYPE(so), error));
		goto out;
	}

	/* Socket filter */
	error = sflt_bind(so, nam);

	if (error == 0)
		error = (*so->so_proto->pr_usrreqs->pru_bind)(so, nam, p);
out:
	if (dolock)
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

#if CONTENT_FILTER
	cfil_sock_detach(so);
#endif /* CONTENT_FILTER */

	/* Delete the state allocated for msg queues on a socket */
	if (so->so_flags & SOF_ENABLE_MSGS) {
		FREE(so->so_msg_state, M_TEMP);
		so->so_msg_state = NULL;
	}
	VERIFY(so->so_msg_state == NULL);

	so->so_gencnt = OSIncrementAtomic64((SInt64 *)&so_gencnt);

#if CONFIG_MACF_SOCKET
	mac_socket_label_destroy(so);
#endif /* MAC_SOCKET */

	if (so->so_flags1 & SOF1_CACHED_IN_SOCK_LAYER) {
		cached_sock_free(so);
	} else {
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

	so_update_last_owner_locked(so, p);
	so_update_policy(so);

#if NECP
	so_update_necp_policy(so, NULL, NULL);
#endif /* NECP */

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
			SODEFUNCTLOG(("%s[%d]: defunct so 0x%llx [%d,%d] "
			    "(%d)\n", __func__, proc_pid(p),
			    (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
			    SOCK_DOM(so), SOCK_TYPE(so), error));
		}
		goto out;
	}

	if ((so->so_restrictions & SO_RESTRICT_DENY_IN) != 0) {
		error = EPERM;
		goto out;
	}

	error = sflt_listen(so);
	if (error == 0)
		error = (*so->so_proto->pr_usrreqs->pru_listen)(so, p);

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

	if (!(so->so_flags & SOF_PCBCLEARING) || !(so->so_state & SS_NOFDREF)) {
		selthreadclear(&so->so_snd.sb_sel);
		selthreadclear(&so->so_rcv.sb_sel);
		so->so_rcv.sb_flags &= ~(SB_SEL|SB_UPCALL);
		so->so_snd.sb_flags &= ~(SB_SEL|SB_UPCALL);
		so->so_event = sonullevent;
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
			selthreadclear(&so->so_snd.sb_sel);
			selthreadclear(&so->so_rcv.sb_sel);
			so->so_rcv.sb_flags &= ~(SB_SEL|SB_UPCALL);
			so->so_snd.sb_flags &= ~(SB_SEL|SB_UPCALL);
			so->so_event = sonullevent;
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
	sowflush(so);
	sorflush(so);

#if FLOW_DIVERT
	if (so->so_flags & SOF_FLOW_DIVERT) {
		flow_divert_detach(so);
	}
#endif	/* FLOW_DIVERT */

	/* 3932268: disable upcall */
	so->so_rcv.sb_flags &= ~SB_UPCALL;
	so->so_snd.sb_flags &= ~SB_UPCALL;
	so->so_event = sonullevent;

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
	(void) msleep((caddr_t)&so->so_upcallusecount, mutex_held, (PZERO - 1),
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
		/* NOTREACHED */
	}

	sflt_notify(so, sock_evt_closing, NULL);

	if (so->so_upcallusecount)
		soclose_wait_locked(so);

#if CONTENT_FILTER
	/*
	 * We have to wait until the content filters are done
	 */
	if ((so->so_flags & SOF_CONTENT_FILTER) != 0) {
		cfil_sock_close_wait(so);
		cfil_sock_is_closed(so);
		cfil_sock_detach(so);
	}
#endif /* CONTENT_FILTER */

	if (so->so_flags1 & SOF1_EXTEND_BK_IDLE_INPROG) {
		soresume(current_proc(), so, 1);
		so->so_flags1 &= ~SOF1_EXTEND_BK_IDLE_WANTED;
	}

	if ((so->so_options & SO_ACCEPTCONN)) {
		struct socket *sp, *sonext;
		int socklock = 0;

		/*
		 * We do not want new connection to be added
		 * to the connection queues
		 */
		so->so_options &= ~SO_ACCEPTCONN;

		for (sp = TAILQ_FIRST(&so->so_incomp);
		    sp != NULL; sp = sonext) {
			sonext = TAILQ_NEXT(sp, so_list);

			/*
			 * Radar 5350314
			 * skip sockets thrown away by tcpdropdropblreq
			 * they will get cleanup by the garbage collection.
			 * otherwise, remove the incomp socket from the queue
			 * and let soabort trigger the appropriate cleanup.
			 */
			if (sp->so_flags & SOF_OVERFLOW)
				continue;

			if (so->so_proto->pr_getlock != NULL) {
				/*
				 * Lock ordering for consistency with the
				 * rest of the stack, we lock the socket
				 * first and then grabb the head.
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
	if (so->so_pcb == NULL) {
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
	if (so->so_usecount == 0) {
		panic("soclose: usecount is zero so=%p\n", so);
		/* NOTREACHED */
	}
	if (so->so_pcb != NULL && !(so->so_flags & SOF_PCBCLEARING)) {
		int error2 = (*so->so_proto->pr_usrreqs->pru_detach)(so);
		if (error == 0)
			error = error2;
	}
	if (so->so_usecount <= 0) {
		panic("soclose: usecount is zero so=%p\n", so);
		/* NOTREACHED */
	}
discard:
	if (so->so_pcb != NULL && !(so->so_flags & SOF_MP_SUBFLOW) &&
	    (so->so_state & SS_NOFDREF)) {
		panic("soclose: NOFDREF");
		/* NOTREACHED */
	}
	so->so_state |= SS_NOFDREF;

	if (so->so_flags & SOF_MP_SUBFLOW)
		so->so_flags &= ~SOF_MP_SUBFLOW;

	if ((so->so_flags & SOF_KNOTE) != 0)
		KNOTE(&so->so_klist, SO_FILT_HINT_LOCKED);

	atomic_add_32(&so->so_proto->pr_domain->dom_refs, -1);
	evsofree(so);

	so->so_usecount--;
	sofree(so);
	return (error);
}

int
soclose(struct socket *so)
{
	int error = 0;
	socket_lock(so, 1);

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

	so_update_last_owner_locked(so, PROC_NULL);
	so_update_policy(so);
#if NECP
	so_update_necp_policy(so, NULL, NULL);
#endif /* NECP */

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
	 * Hold the lock even if this socket has not been made visible
	 * to the filter(s).  For sockets with global locks, this protects
	 * against the head or peer going away
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

	so_update_last_owner_locked(so, p);
	so_update_policy(so);

#if NECP
	so_update_necp_policy(so, NULL, nam);
#endif /* NECP */

	/*
	 * If this is a listening socket or if this is a previously-accepted
	 * socket that has been marked as inactive, reject the connect request.
	 */
	if ((so->so_options & SO_ACCEPTCONN) || (so->so_flags & SOF_DEFUNCT)) {
		error = EOPNOTSUPP;
		if (so->so_flags & SOF_DEFUNCT) {
			SODEFUNCTLOG(("%s[%d]: defunct so 0x%llx [%d,%d] "
			    "(%d)\n", __func__, proc_pid(p),
			    (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
			    SOCK_DOM(so), SOCK_TYPE(so), error));
		}
		if (dolock)
			socket_unlock(so, 1);
		return (error);
	}

	if ((so->so_restrictions & SO_RESTRICT_DENY_OUT) != 0) {
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
		if (error != 0) {
			if (error == EJUSTRETURN)
				error = 0;
		} else {
			error = (*so->so_proto->pr_usrreqs->pru_connect)
			    (so, nam, p);
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
soconnectxlocked(struct socket *so, struct sockaddr_list **src_sl,
    struct sockaddr_list **dst_sl, struct proc *p, uint32_t ifscope,
    sae_associd_t aid, sae_connid_t *pcid, uint32_t flags, void *arg,
    uint32_t arglen, uio_t auio, user_ssize_t *bytes_written)
{
	int error;

	so_update_last_owner_locked(so, p);
	so_update_policy(so);

	/*
	 * If this is a listening socket or if this is a previously-accepted
	 * socket that has been marked as inactive, reject the connect request.
	 */
	if ((so->so_options & SO_ACCEPTCONN) || (so->so_flags & SOF_DEFUNCT)) {
		error = EOPNOTSUPP;
		if (so->so_flags & SOF_DEFUNCT) {
			SODEFUNCTLOG(("%s[%d]: defunct so 0x%llx [%d,%d] "
			    "(%d)\n", __func__, proc_pid(p),
			    (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
			    SOCK_DOM(so), SOCK_TYPE(so), error));
		}
		return (error);
	}

	if ((so->so_restrictions & SO_RESTRICT_DENY_OUT) != 0)
		return (EPERM);

	/*
	 * If protocol is connection-based, can only connect once
	 * unless PR_MULTICONN is set.  Otherwise, if connected,
	 * try to disconnect first.  This allows user to disconnect
	 * by connecting to, e.g., a null address.
	 */
	if ((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) &&
	    !(so->so_proto->pr_flags & PR_MULTICONN) &&
	    ((so->so_proto->pr_flags & PR_CONNREQUIRED) ||
	    (error = sodisconnectlocked(so)) != 0)) {
		error = EISCONN;
	} else {
		/*
		 * Run connect filter before calling protocol:
		 *  - non-blocking connect returns before completion;
		 */
		error = sflt_connectxout(so, dst_sl);
		if (error != 0) {
			/* Disable PRECONNECT_DATA, as we don't need to send a SYN anymore. */
			so->so_flags1 &= ~SOF1_PRECONNECT_DATA;
			if (error == EJUSTRETURN)
				error = 0;
		} else {
			error = (*so->so_proto->pr_usrreqs->pru_connectx)
			    (so, src_sl, dst_sl, p, ifscope, aid, pcid,
			    flags, arg, arglen, auio, bytes_written);
		}
	}

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
	if (error == 0)
		sflt_notify(so, sock_evt_disconnected, NULL);

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

int
sodisconnectxlocked(struct socket *so, sae_associd_t aid, sae_connid_t cid)
{
	int error;

	/*
	 * Call the protocol disconnectx handler; let it handle all
	 * matters related to the connection state of this session.
	 */
	error = (*so->so_proto->pr_usrreqs->pru_disconnectx)(so, aid, cid);
	if (error == 0) {
		/*
		 * The event applies only for the session, not for
		 * the disconnection of individual subflows.
		 */
		if (so->so_state & (SS_ISDISCONNECTING|SS_ISDISCONNECTED))
			sflt_notify(so, sock_evt_disconnected, NULL);
	}
	return (error);
}

int
sodisconnectx(struct socket *so, sae_associd_t aid, sae_connid_t cid)
{
	int error;

	socket_lock(so, 1);
	error = sodisconnectxlocked(so, aid, cid);
	socket_unlock(so, 1);
	return (error);
}

int
sopeelofflocked(struct socket *so, sae_associd_t aid, struct socket **psop)
{
	return ((*so->so_proto->pr_usrreqs->pru_peeloff)(so, aid, psop));
}

#define	SBLOCKWAIT(f)	(((f) & MSG_DONTWAIT) ? 0 : SBL_WAIT)

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
int
sosendcheck(struct socket *so, struct sockaddr *addr, user_ssize_t resid,
    int32_t clen, int32_t atomic, int flags, int *sblocked,
    struct mbuf *control)
{
	int	error = 0;
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
		SODEFUNCTLOG(("%s[%d]: defunct so 0x%llx [%d,%d] (%d)\n",
		    __func__, proc_selfpid(),
		    (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
		    SOCK_DOM(so), SOCK_TYPE(so), error));
		return (error);
	}

	if (so->so_state & SS_CANTSENDMORE) {
#if CONTENT_FILTER
		/*
		 * Can re-inject data of half closed connections
		 */
		if ((so->so_state & SS_ISDISCONNECTED) == 0 &&
			so->so_snd.sb_cfil_thread == current_thread() &&
			cfil_sock_data_pending(&so->so_snd) != 0)
			CFIL_LOG(LOG_INFO,
				"so %llx ignore SS_CANTSENDMORE",
				(uint64_t)DEBUG_KERNEL_ADDRPERM(so));
		else
#endif /* CONTENT_FILTER */
			return (EPIPE);
	}
	if (so->so_error) {
		error = so->so_error;
		so->so_error = 0;
		return (error);
	}

	if ((so->so_state & SS_ISCONNECTED) == 0) {
		if ((so->so_proto->pr_flags & PR_CONNREQUIRED) != 0) {
			if (((so->so_state & SS_ISCONFIRMING) == 0) &&
			    (resid != 0 || clen == 0) &&
			    !(so->so_flags1 & SOF1_PRECONNECT_DATA)) {
#if MPTCP
				/*
				 * MPTCP Fast Join sends data before the
				 * socket is truly connected.
				 */
				if ((so->so_flags & (SOF_MP_SUBFLOW |
					SOF_MPTCP_FASTJOIN)) !=
				    (SOF_MP_SUBFLOW | SOF_MPTCP_FASTJOIN))
#endif /* MPTCP */
				return (ENOTCONN);
			}
		} else if (addr == 0 && !(flags&MSG_HOLD)) {
			return ((so->so_proto->pr_flags & PR_CONNREQUIRED) ?
			    ENOTCONN : EDESTADDRREQ);
		}
	}

	if (so->so_flags & SOF_ENABLE_MSGS)
		space = msgq_sbspace(so, control);
	else
		space = sbspace(&so->so_snd);

	if (flags & MSG_OOB)
		space += 1024;
	if ((atomic && resid > so->so_snd.sb_hiwat) ||
	    clen > so->so_snd.sb_hiwat)
		return (EMSGSIZE);

	if ((space < resid + clen &&
	    (atomic || (space < (int32_t)so->so_snd.sb_lowat) ||
	    space < clen)) ||
	    (so->so_type == SOCK_STREAM && so_wait_for_if_feedback(so))) {
		/*
		 * don't block the connectx call when there's more data
		 * than can be copied.
		 */
		if (so->so_flags1 & SOF1_PRECONNECT_DATA) {
			if (space == 0) {
				return (EWOULDBLOCK);
			}
			if (space < (int32_t)so->so_snd.sb_lowat) {
				return (0);
			}
		}
		if ((so->so_state & SS_NBIO) || (flags & MSG_NBIO) ||
		    assumelock) {
			return (EWOULDBLOCK);
		}
		sbunlock(&so->so_snd, TRUE);	/* keep socket locked */
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
	struct mbuf *m, *freelist = NULL;
	user_ssize_t space, len, resid, orig_resid;
	int clen = 0, error, dontroute, mlen, sendflags;
	int atomic = sosendallatonce(so) || top;
	int sblocked = 0;
	struct proc *p = current_proc();
	struct mbuf *control_copy = NULL;
	uint16_t headroom = 0;
	boolean_t en_tracing = FALSE;

	if (uio != NULL)
		resid = uio_resid(uio);
	else
		resid = top->m_pkthdr.len;

	KERNEL_DEBUG((DBG_FNC_SOSEND | DBG_FUNC_START), so, resid,
	    so->so_snd.sb_cc, so->so_snd.sb_lowat, so->so_snd.sb_hiwat);

	socket_lock(so, 1);

	/*
	 * trace if tracing & network (vs. unix) sockets & and
	 * non-loopback
	 */
	if (ENTR_SHOULDTRACE &&
	    (SOCK_CHECK_DOM(so, AF_INET) || SOCK_CHECK_DOM(so, AF_INET6))) {
		struct inpcb *inp = sotoinpcb(so);
		if (inp->inp_last_outifp != NULL &&
		    !(inp->inp_last_outifp->if_flags & IFF_LOOPBACK)) {
			en_tracing = TRUE;
			KERNEL_ENERGYTRACE(kEnTrActKernSockWrite, DBG_FUNC_START,
			    VM_KERNEL_ADDRPERM(so),
			    ((so->so_state & SS_NBIO) ? kEnTrFlagNonBlocking : 0),
			    (int64_t)resid);
			orig_resid = resid;
		}
	}

	/*
	 * Re-injection should not affect process accounting
	 */
	if ((flags & MSG_SKIPCFIL) == 0) {
		so_update_last_owner_locked(so, p);
		so_update_policy(so);

#if NECP
		so_update_necp_policy(so, NULL, addr);
#endif /* NECP */
	}

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
	 * Usually, MSG_EOR isn't used on SOCK_STREAM type sockets.
	 * But it will be used by sockets doing message delivery.
	 *
	 * Note: We limit resid to be a positive int value as we use
	 * imin() to set bytes_to_copy -- radr://14558484
	 */
	if (resid < 0 || resid > INT_MAX || (so->so_type == SOCK_STREAM &&
	    !(so->so_flags & SOF_ENABLE_MSGS) && (flags & MSG_EOR))) {
		error = EINVAL;
		socket_unlock(so, 1);
		goto out;
	}

	dontroute = (flags & MSG_DONTROUTE) &&
	    (so->so_options & SO_DONTROUTE) == 0 &&
	    (so->so_proto->pr_flags & PR_ATOMIC);
	OSIncrementAtomicLong(&p->p_stats->p_ru.ru_msgsnd);

	if (control != NULL)
		clen = control->m_len;

	if (soreserveheadroom != 0)
		headroom = so->so_pktheadroom;

	do {
		error = sosendcheck(so, addr, resid, clen, atomic, flags,
		    &sblocked, control);
		if (error)
			goto release;

		mp = &top;
		if (so->so_flags & SOF_ENABLE_MSGS)
			space = msgq_sbspace(so, control);
		else
			space = sbspace(&so->so_snd) - clen;
		space += ((flags & MSG_OOB) ? 1024 : 0);

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
				boolean_t bigcl;
				int bytes_to_alloc;

				bytes_to_copy = imin(resid, space);

				bytes_to_alloc = bytes_to_copy;
				if (top == NULL)
					bytes_to_alloc += headroom;

				if (sosendminchain > 0)
					chainlength = 0;
				else
					chainlength = sosendmaxchain;

				/*
				 * Use big 4 KB cluster when the outgoing interface
				 * does not prefer 2 KB clusters
				 */
				bigcl = !(so->so_flags1 & SOF1_IF_2KCL) ||
				    sosendbigcl_ignore_capab;

				/*
				 * Attempt to use larger than system page-size
				 * clusters for large writes only if there is
				 * a jumbo cluster pool and if the socket is
				 * marked accordingly.
				 */
				jumbocl = sosendjcl && njcl > 0 &&
				    ((so->so_flags & SOF_MULTIPAGES) ||
				    sosendjcl_ignore_capab) &&
				    bigcl;

				socket_unlock(so, 0);

				do {
					int num_needed;
					int hdrs_needed = (top == NULL) ? 1 : 0;

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
					    bytes_to_alloc > MBIGCLBYTES &&
					    jumbocl) {
						num_needed =
						    bytes_to_alloc / M16KCLBYTES;

						if ((bytes_to_alloc -
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
					    bytes_to_alloc > MCLBYTES &&
					    bigcl) {
						num_needed =
						    bytes_to_alloc / MBIGCLBYTES;

						if ((bytes_to_alloc -
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

					/*
					 * Allocate a cluster as we want to
					 * avoid to split the data in more
					 * that one segment and using MINCLSIZE
					 * would lead us to allocate two mbufs
					 */
					if (soreserveheadroom != 0 &&
					    freelist == NULL &&
					    ((top == NULL &&
					    bytes_to_alloc > _MHLEN) ||
					    bytes_to_alloc > _MLEN)) {
						num_needed = ROUNDUP(bytes_to_alloc, MCLBYTES) /
						    MCLBYTES;
						freelist =
						    m_getpackets_internal(
						    (unsigned int *)&num_needed,
						    hdrs_needed, M_WAIT, 0,
						    MCLBYTES);
						/*
						 * Fall back to a single mbuf
						 * if allocation failed
						 */
					} else if (freelist == NULL &&
					    bytes_to_alloc > MINCLSIZE) {
						num_needed =
						    bytes_to_alloc / MCLBYTES;

						if ((bytes_to_alloc -
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
					/*
					 * For datagram protocols, leave
					 * headroom for protocol headers
					 * in the first cluster of the chain
					 */
					if (freelist != NULL && atomic &&
					    top == NULL && headroom > 0) {
						freelist->m_data += headroom;
					}
					
					/*
					 * Fall back to regular mbufs without
					 * reserving the socket headroom
					 */
					if (freelist == NULL) {
						if (top == NULL)
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
						if (atomic && top == NULL &&
						    bytes_to_copy < MHLEN) {
							MH_ALIGN(freelist,
							    bytes_to_copy);
						}
					}
					m = freelist;
					freelist = m->m_next;
					m->m_next = NULL;

					if ((m->m_flags & M_EXT))
						mlen = m->m_ext.ext_size -
						    m_leadingspace(m);
					else if ((m->m_flags & M_PKTHDR))
						mlen =
						    MHLEN - m_leadingspace(m);
					else
						mlen = MLEN - m_leadingspace(m);
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
				struct mbuf *mb1;
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

			/*
			 * Compute flags here, for pru_send and NKEs
			 *
			 * If the user set MSG_EOF, the protocol
			 * understands this flag and nothing left to
			 * send then use PRU_SEND_EOF instead of PRU_SEND.
			 */
			sendflags = (flags & MSG_OOB) ? PRUS_OOB :
			    ((flags & MSG_EOF) &&
			    (so->so_proto->pr_flags & PR_IMPLOPCL) &&
			    (resid <= 0)) ? PRUS_EOF :
			    /* If there is more to send set PRUS_MORETOCOME */
			    (resid > 0 && space > 0) ? PRUS_MORETOCOME : 0;

			if ((flags & MSG_SKIPCFIL) == 0) {
				/*
				 * Socket filter processing
				 */
				error = sflt_data_out(so, addr, &top,
				    &control, (sendflags & MSG_OOB) ?
				    sock_data_filt_flag_oob : 0);
				if (error) {
					if (error == EJUSTRETURN) {
						error = 0;
						clen = 0;
						control = NULL;
						top = NULL;
					}
					goto release;
				}
#if CONTENT_FILTER
				/*
				 * Content filter processing
				 */
				error = cfil_sock_data_out(so, addr, top,
				    control, (sendflags & MSG_OOB) ?
				    sock_data_filt_flag_oob : 0);
				if (error) {
					if (error == EJUSTRETURN) {
						error = 0;
						clen = 0;
						control = NULL;
						top = NULL;
						}
					goto release;
				}
#endif /* CONTENT_FILTER */
			}
			if (so->so_flags & SOF_ENABLE_MSGS) {
				/*
				 * Make a copy of control mbuf,
				 * so that msg priority can be
				 * passed to subsequent mbufs.
				 */
				control_copy = m_dup(control, M_NOWAIT);
			}
			error = (*so->so_proto->pr_usrreqs->pru_send)
			    (so, sendflags, top, addr, control, p);

			if (flags & MSG_SEND)
				so->so_temp = NULL;

			if (dontroute)
				so->so_options &= ~SO_DONTROUTE;

			clen = 0;
			control = control_copy;
			control_copy = NULL;
			top = NULL;
			mp = &top;
			if (error)
				goto release;
		} while (resid && space > 0);
	} while (resid);

release:
	if (sblocked)
		sbunlock(&so->so_snd, FALSE);	/* will unlock socket */
	else
		socket_unlock(so, 1);
out:
	if (top != NULL)
		m_freem(top);
	if (control != NULL)
		m_freem(control);
	if (freelist != NULL)
		m_freem_list(freelist);
	if (control_copy != NULL)
		m_freem(control_copy);

	/*
	 * One write has been done. This was enough. Get back to "normal"
	 * behavior.
	 */
	if (so->so_flags1 & SOF1_PRECONNECT_DATA)
		so->so_flags1 &= ~SOF1_PRECONNECT_DATA;

	if (en_tracing) {
		/* resid passed here is the bytes left in uio */
		KERNEL_ENERGYTRACE(kEnTrActKernSockWrite, DBG_FUNC_END,
		    VM_KERNEL_ADDRPERM(so),
		    ((error == EWOULDBLOCK) ? kEnTrFlagNoWork : 0),
		    (int64_t)(orig_resid - resid));
	}
	KERNEL_DEBUG(DBG_FNC_SOSEND | DBG_FUNC_END, so, resid,
	    so->so_snd.sb_cc, space, error);

	return (error);
}

/*
 * Supported only connected sockets (no address) without ancillary data
 * (control mbuf) for atomic protocols
 */
int
sosend_list(struct socket *so, struct uio **uioarray, u_int uiocnt, int flags)
{
	struct mbuf *m, *freelist = NULL;
	user_ssize_t len, resid;
	int error, dontroute, mlen;
	int atomic = sosendallatonce(so);
	int sblocked = 0;
	struct proc *p = current_proc();
	u_int uiofirst = 0;
	u_int uiolast = 0;
	struct mbuf *top = NULL;
	uint16_t headroom = 0;
	boolean_t bigcl;

	KERNEL_DEBUG((DBG_FNC_SOSEND_LIST | DBG_FUNC_START), so, uiocnt,
	    so->so_snd.sb_cc, so->so_snd.sb_lowat, so->so_snd.sb_hiwat);

	if (so->so_type != SOCK_DGRAM) {
		error = EINVAL;
		goto out;
	}
	if (atomic == 0) {
		error = EINVAL;
		goto out;
	}
	if (so->so_proto->pr_usrreqs->pru_send_list == NULL) {
		error = EPROTONOSUPPORT;
		goto out;
	}
	if (flags & ~(MSG_DONTWAIT | MSG_NBIO)) {
		error = EINVAL;
		goto out;
	}
	resid = uio_array_resid(uioarray, uiocnt);

	/*
	 * In theory resid should be unsigned.
	 * However, space must be signed, as it might be less than 0
	 * if we over-committed, and we must use a signed comparison
	 * of space and resid.  On the other hand, a negative resid
	 * causes us to loop sending 0-length segments to the protocol.
	 *
	 * Note: We limit resid to be a positive int value as we use
	 * imin() to set bytes_to_copy -- radr://14558484
	 */
	if (resid < 0 || resid > INT_MAX) {
		error = EINVAL;
		goto out;
	}

	socket_lock(so, 1);
	so_update_last_owner_locked(so, p);
	so_update_policy(so);

#if NECP
	so_update_necp_policy(so, NULL, NULL);
#endif /* NECP */

	dontroute = (flags & MSG_DONTROUTE) &&
	    (so->so_options & SO_DONTROUTE) == 0 &&
	    (so->so_proto->pr_flags & PR_ATOMIC);
	OSIncrementAtomicLong(&p->p_stats->p_ru.ru_msgsnd);

	error = sosendcheck(so, NULL, resid, 0, atomic, flags,
	    &sblocked, NULL);
	if (error)
		goto release;

	/*
	 * Use big 4 KB clusters when the outgoing interface does not prefer
	 * 2 KB clusters
	 */
	bigcl = !(so->so_flags1 & SOF1_IF_2KCL) || sosendbigcl_ignore_capab;

	if (soreserveheadroom != 0)
		headroom = so->so_pktheadroom;

	do {
		int i;
		int num_needed = 0;
		int chainlength;
		size_t maxpktlen = 0;
		int bytes_to_alloc;

		if (sosendminchain > 0)
			chainlength = 0;
		else
			chainlength = sosendmaxchain;

		socket_unlock(so, 0);

		/*
		 * Find a set of uio that fit in a reasonable number
		 * of mbuf packets
		 */
		for (i = uiofirst; i < uiocnt; i++) {
			struct uio *auio = uioarray[i];

			len = uio_resid(auio);

			/* Do nothing for empty messages */
			if (len == 0)
				continue;

			num_needed += 1;
			uiolast += 1;

			if (len > maxpktlen)
				maxpktlen = len;

			chainlength += len;
			if (chainlength > sosendmaxchain)
				break;
		}
		/*
		 * Nothing left to send
		 */
		if (num_needed == 0) {
			socket_lock(so, 0);
			break;
		}
		/*
		 * Allocate buffer large enough to include headroom space for
		 * network and link header
		 * 
		 */
		bytes_to_alloc = maxpktlen + headroom;

		/*
		 * Allocate a single contiguous buffer of the smallest available
		 * size when possible
		 */
		if (bytes_to_alloc > MCLBYTES &&
		    bytes_to_alloc <= MBIGCLBYTES && bigcl) {
			freelist = m_getpackets_internal(
			    (unsigned int *)&num_needed,
			    num_needed, M_WAIT, 1,
			    MBIGCLBYTES);
		} else if (bytes_to_alloc > _MHLEN &&
		    bytes_to_alloc <= MCLBYTES) {
			freelist = m_getpackets_internal(
			    (unsigned int *)&num_needed,
			    num_needed, M_WAIT, 1,
			    MCLBYTES);
		} else {
			freelist = m_allocpacket_internal(
			    (unsigned int *)&num_needed,
			    bytes_to_alloc, NULL, M_WAIT, 1, 0);
		}
		
		if (freelist == NULL) {
			socket_lock(so, 0);
			error = ENOMEM;
			goto release;
		}
		/*
		 * Copy each uio of the set into its own mbuf packet
		 */
		for (i = uiofirst, m = freelist;
		    i < uiolast && m != NULL;
		    i++) {
			int bytes_to_copy;
			struct mbuf *n;
			struct uio *auio = uioarray[i];

			bytes_to_copy = uio_resid(auio);

			/* Do nothing for empty messages */
			if (bytes_to_copy == 0)
				continue;
			/*
			 * Leave headroom for protocol headers
			 * in the first mbuf of the chain
			 */
			m->m_data += headroom;

			for (n = m; n != NULL; n = n->m_next) {
				if ((m->m_flags & M_EXT))
					mlen = m->m_ext.ext_size -
					    m_leadingspace(m);
				else if ((m->m_flags & M_PKTHDR))
					mlen =
					    MHLEN - m_leadingspace(m);
				else
					mlen = MLEN - m_leadingspace(m);
				len = imin(mlen, bytes_to_copy);

				/*
				 * Note: uiomove() decrements the iovec
				 * length
				 */
				error = uiomove(mtod(n, caddr_t),
				    len, auio);
				if (error != 0)
					break;
				n->m_len = len;
				m->m_pkthdr.len += len;

				VERIFY(m->m_pkthdr.len <= maxpktlen);

				bytes_to_copy -= len;
				resid -= len;
			}
			if (m->m_pkthdr.len == 0) {
				printf(
				    "%s:%d so %llx pkt %llx type %u len null\n",
				    __func__, __LINE__,
				    (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
				    (uint64_t)DEBUG_KERNEL_ADDRPERM(m),
				    m->m_type);
			}
			if (error != 0)
				break;
			m = m->m_nextpkt;
		}

		socket_lock(so, 0);

		if (error)
			goto release;
		top = freelist;
		freelist = NULL;

		if (dontroute)
			so->so_options |= SO_DONTROUTE;

		if ((flags & MSG_SKIPCFIL) == 0) {
			struct mbuf **prevnextp = NULL;

			for (i = uiofirst, m = top;
			    i < uiolast && m != NULL;
			    i++) {
				struct mbuf *nextpkt = m->m_nextpkt;

				/*
				 * Socket filter processing
				 */
				error = sflt_data_out(so, NULL, &m,
				    NULL, 0);
				if (error != 0 && error != EJUSTRETURN)
					goto release;

#if CONTENT_FILTER
				if (error == 0) {
					/*
					 * Content filter processing
					 */
					error = cfil_sock_data_out(so, NULL, m,
					    NULL, 0);
					if (error != 0 && error != EJUSTRETURN)
						goto release;
				}
#endif /* CONTENT_FILTER */
				/*
				 * Remove packet from the list when
				 * swallowed by a filter
				 */
				if (error == EJUSTRETURN) {
					error = 0;
					if (prevnextp != NULL)
						*prevnextp = nextpkt;
					else
						top = nextpkt;
				}

				m = nextpkt;
				if (m != NULL)
					prevnextp = &m->m_nextpkt;
			}
		}
		if (top != NULL)
			error = (*so->so_proto->pr_usrreqs->pru_send_list)
			    (so, 0, top, NULL, NULL, p);

		if (dontroute)
			so->so_options &= ~SO_DONTROUTE;

		top = NULL;
		uiofirst = uiolast;
	} while (resid > 0 && error == 0);
release:
	if (sblocked)
		sbunlock(&so->so_snd, FALSE);	/* will unlock socket */
	else
		socket_unlock(so, 1);
out:
	if (top != NULL)
		m_freem(top);
	if (freelist != NULL)
		m_freem_list(freelist);

	KERNEL_DEBUG(DBG_FNC_SOSEND_LIST | DBG_FUNC_END, so, resid,
	    so->so_snd.sb_cc, 0, error);

	return (error);
}

/*
 * May return ERESTART when packet is dropped by MAC policy check
 */
static int
soreceive_addr(struct proc *p, struct socket *so, struct sockaddr **psa,
    int flags, struct mbuf **mp, struct mbuf **nextrecordp, int canwait)
{
	int error = 0;
	struct mbuf *m = *mp;
	struct mbuf *nextrecord = *nextrecordp;

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
			m_freem(m);
			/*
			 * Clear SB_LOCK but don't unlock the socket.
			 * Process the next record or wait for one.
			 */
			socket_lock(so, 0);
			sbunlock(&so->so_rcv, TRUE); /* stay locked */
			error = ERESTART;
			goto done;
		}
		socket_lock(so, 0);
		/*
		 * If the socket has been defunct'd, drop it.
		 */
		if (so->so_flags & SOF_DEFUNCT) {
			m_freem(m);
			error = ENOTCONN;
			goto done;
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
	if (psa != NULL) {
		*psa = dup_sockaddr(mtod(m, struct sockaddr *), canwait);
		if ((*psa == NULL) && (flags & MSG_NEEDSA)) {
			error = EWOULDBLOCK;
			goto done;
		}
	}
	if (flags & MSG_PEEK) {
		m = m->m_next;
	} else {
		sbfree(&so->so_rcv, m);
		if (m->m_next == NULL && so->so_rcv.sb_cc != 0) {
			panic("%s: about to create invalid socketbuf",
			    __func__);
			/* NOTREACHED */
		}
		MFREE(m, so->so_rcv.sb_mb);
		m = so->so_rcv.sb_mb;
		if (m != NULL) {
			m->m_nextpkt = nextrecord;
		} else {
			so->so_rcv.sb_mb = nextrecord;
			SB_EMPTY_FIXUP(&so->so_rcv);
		}
	}
done:
	*mp = m;
	*nextrecordp = nextrecord;

	return (error);
}

/*
 * Process one or more MT_CONTROL mbufs present before any data mbufs
 * in the first mbuf chain on the socket buffer.  If MSG_PEEK, we
 * just copy the data; if !MSG_PEEK, we call into the protocol to
 * perform externalization.
 */
static int
soreceive_ctl(struct socket *so, struct mbuf **controlp, int flags,
    struct mbuf **mp, struct mbuf **nextrecordp)
{
	int error = 0;
	struct mbuf *cm = NULL, *cmn;
	struct mbuf **cme = &cm;
	struct sockbuf *sb_rcv = &so->so_rcv;
	struct mbuf **msgpcm = NULL;
	struct mbuf *m = *mp;
	struct mbuf *nextrecord = *nextrecordp;
	struct protosw *pr = so->so_proto;

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

				/*
				 * If we failed to allocate an mbuf,
				 * release any previously allocated
				 * mbufs for control data. Return
				 * an error. Keep the mbufs in the
				 * socket as this is using
				 * MSG_PEEK flag.
				 */
				if (*controlp == NULL) {
					m_freem(*msgpcm);
					error = ENOBUFS;
					goto done;
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

done:
	*mp = m;
	*nextrecordp = nextrecord;

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
	struct mbuf *m, **mp, *ml = NULL;
	struct mbuf *nextrecord, *free_list;
	int flags, error, offset;
	user_ssize_t len;
	struct protosw *pr = so->so_proto;
	int moff, type = 0;
	user_ssize_t orig_resid = uio_resid(uio);
	user_ssize_t delayed_copy_len;
	int can_delay;
	int need_event;
	struct proc *p = current_proc();
	boolean_t en_tracing = FALSE;

	/*
	 * Sanity check on the length passed by caller as we are making 'int'
	 * comparisons
	 */
	if (orig_resid < 0 || orig_resid > INT_MAX)
		return (EINVAL);

	KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_START, so,
	    uio_resid(uio), so->so_rcv.sb_cc, so->so_rcv.sb_lowat,
	    so->so_rcv.sb_hiwat);

	socket_lock(so, 1);
	so_update_last_owner_locked(so, p);
	so_update_policy(so);

#ifdef MORE_LOCKING_DEBUG
	if (so->so_usecount == 1) {
		panic("%s: so=%x no other reference on socket\n", __func__, so);
		/* NOTREACHED */
	}
#endif
	mp = mp0;
	if (psa != NULL)
		*psa = NULL;
	if (controlp != NULL)
		*controlp = NULL;
	if (flagsp != NULL)
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
		SODEFUNCTLOG(("%s[%d]: defunct so 0x%llx [%d,%d] (%d)\n",
		    __func__, proc_pid(p), (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
		    SOCK_DOM(so), SOCK_TYPE(so), error));
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

	if ((so->so_flags1 & SOF1_PRECONNECT_DATA) &&
	    pr->pr_usrreqs->pru_preconnect) {
		/*
		 * A user may set the CONNECT_RESUME_ON_READ_WRITE-flag but not
		 * calling write() right after this. *If* the app calls a read
		 * we do not want to block this read indefinetely. Thus,
		 * we trigger a connect so that the session gets initiated.
		 */
		error = (*pr->pr_usrreqs->pru_preconnect)(so);

		if (error) {
			socket_unlock(so, 1);
			return (error);
		}
	}

	if (ENTR_SHOULDTRACE &&
	    (SOCK_CHECK_DOM(so, AF_INET) || SOCK_CHECK_DOM(so, AF_INET6))) {
		/*
		 * enable energy tracing for inet sockets that go over
		 * non-loopback interfaces only.
		 */
		struct inpcb *inp = sotoinpcb(so);
		if (inp->inp_last_outifp != NULL &&
		    !(inp->inp_last_outifp->if_flags & IFF_LOOPBACK)) {
			en_tracing = TRUE;
			KERNEL_ENERGYTRACE(kEnTrActKernSockRead, DBG_FUNC_START,
			    VM_KERNEL_ADDRPERM(so),
			    ((so->so_state & SS_NBIO) ?
			    kEnTrFlagNonBlocking : 0),
			    (int64_t)orig_resid);
		}
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
		} while (uio_resid(uio) && error == 0 && m != NULL);
		socket_lock(so, 0);
bad:
		if (m != NULL)
			m_freem(m);

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
			} else if (error == 0 && flagsp != NULL) {
				*flagsp |= MSG_OOB;
			}
		}
		socket_unlock(so, 1);
		if (en_tracing) {
			KERNEL_ENERGYTRACE(kEnTrActKernSockRead, DBG_FUNC_END,
			    VM_KERNEL_ADDRPERM(so), 0,
			    (int64_t)(orig_resid - uio_resid(uio)));
		}
		KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, error,
		    0, 0, 0, 0);

		return (error);
	}
nooob:
	if (mp != NULL)
		*mp = NULL;

	if (so->so_state & SS_ISCONFIRMING && uio_resid(uio)) {
		(*pr->pr_usrreqs->pru_rcvd)(so, 0);
	}

	free_list = NULL;
	delayed_copy_len = 0;
restart:
#ifdef MORE_LOCKING_DEBUG
	if (so->so_usecount <= 1)
		printf("soreceive: sblock so=0x%llx ref=%d on socket\n",
		    (uint64_t)DEBUG_KERNEL_ADDRPERM(so), so->so_usecount);
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
	 *
	 * A multipath subflow socket would have its SS_NOFDREF set by
	 * default, so check for SOF_MP_SUBFLOW socket flag; when the
	 * socket is closed for real, SOF_MP_SUBFLOW would be cleared.
	 */
	if ((so->so_state & (SS_NOFDREF | SS_CANTRCVMORE)) ==
	    (SS_NOFDREF | SS_CANTRCVMORE) && !(so->so_flags & SOF_MP_SUBFLOW)) {
		socket_unlock(so, 1);
		return (0);
	}

	error = sblock(&so->so_rcv, SBLOCKWAIT(flags));
	if (error) {
		socket_unlock(so, 1);
		KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, error,
		    0, 0, 0, 0);
		if (en_tracing) {
			KERNEL_ENERGYTRACE(kEnTrActKernSockRead, DBG_FUNC_END,
			    VM_KERNEL_ADDRPERM(so), 0,
			    (int64_t)(orig_resid - uio_resid(uio)));
		}
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
	if (m == NULL || (((flags & MSG_DONTWAIT) == 0 &&
	    so->so_rcv.sb_cc < uio_resid(uio)) &&
	    (so->so_rcv.sb_cc < so->so_rcv.sb_lowat ||
	    ((flags & MSG_WAITALL) && uio_resid(uio) <= so->so_rcv.sb_hiwat)) &&
	    m->m_nextpkt == NULL && (pr->pr_flags & PR_ATOMIC) == 0)) {
		/*
		 * Panic if we notice inconsistencies in the socket's
		 * receive list; both sb_mb and sb_cc should correctly
		 * reflect the contents of the list, otherwise we may
		 * end up with false positives during select() or poll()
		 * which could put the application in a bad state.
		 */
		SB_MB_CHECK(&so->so_rcv);

		if (so->so_error) {
			if (m != NULL)
				goto dontblock;
			error = so->so_error;
			if ((flags & MSG_PEEK) == 0)
				so->so_error = 0;
			goto release;
		}
		if (so->so_state & SS_CANTRCVMORE) {
#if CONTENT_FILTER
			/*
			 * Deal with half closed connections
			 */
			if ((so->so_state & SS_ISDISCONNECTED) == 0 &&
				cfil_sock_data_pending(&so->so_rcv) != 0)
				CFIL_LOG(LOG_INFO,
					"so %llx ignore SS_CANTRCVMORE",
					(uint64_t)DEBUG_KERNEL_ADDRPERM(so));
			else
#endif /* CONTENT_FILTER */
			if (m != NULL)
				goto dontblock;
			else
				goto release;
		}
		for (; m != NULL; m = m->m_next)
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
		sbunlock(&so->so_rcv, TRUE);	/* keep socket locked */
#if EVEN_MORE_LOCKING_DEBUG
		if (socket_debug)
			printf("Waiting for socket data\n");
#endif

		error = sbwait(&so->so_rcv);
#if EVEN_MORE_LOCKING_DEBUG
		if (socket_debug)
			printf("SORECEIVE - sbwait returned %d\n", error);
#endif
		if (so->so_usecount < 1) {
			panic("%s: after 2nd sblock so=%p ref=%d on socket\n",
			    __func__, so, so->so_usecount);
			/* NOTREACHED */
		}
		if (error) {
			socket_unlock(so, 1);
			KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, error,
			    0, 0, 0, 0);
			if (en_tracing) {
				KERNEL_ENERGYTRACE(kEnTrActKernSockRead, DBG_FUNC_END,
				    VM_KERNEL_ADDRPERM(so), 0,
				    (int64_t)(orig_resid - uio_resid(uio)));
			}
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
		error = soreceive_addr(p, so, psa, flags, &m, &nextrecord,
		    mp0 == NULL);
		if (error == ERESTART)
			goto restart;
		else if (error != 0)
			goto release;
		orig_resid = 0;
	}

	/*
	 * Process one or more MT_CONTROL mbufs present before any data mbufs
	 * in the first mbuf chain on the socket buffer.  If MSG_PEEK, we
	 * just copy the data; if !MSG_PEEK, we call into the protocol to
	 * perform externalization.
	 */
	if (m != NULL && m->m_type == MT_CONTROL) {
		error = soreceive_ctl(so, controlp, flags, &m, &nextrecord);
		if (error != 0)
			goto release;
		orig_resid = 0;
	}

	/*
	 * If the socket is a TCP socket with message delivery
	 * enabled, then create a control msg to deliver the
	 * relative TCP sequence number for this data. Waiting
	 * until this point will protect against failures to
	 * allocate an mbuf for control msgs.
	 */
	if (so->so_type == SOCK_STREAM && SOCK_PROTO(so) == IPPROTO_TCP &&
	    (so->so_flags & SOF_ENABLE_MSGS) && controlp != NULL) {
		struct mbuf *seq_cm;

		seq_cm = sbcreatecontrol((caddr_t)&m->m_pkthdr.msg_seq,
		    sizeof (uint32_t), SCM_SEQNUM, SOL_SOCKET);
		if (seq_cm == NULL) {
			/* unable to allocate a control mbuf */
			error = ENOBUFS;
			goto release;
		}
		*controlp = seq_cm;
		controlp = &seq_cm->m_next;
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
			if (m != so->so_rcv.sb_mb ||
			    m->m_nextpkt != nextrecord) {
				panic("%s: post-control !sync so=%p m=%p "
				    "nextrecord=%p\n", __func__, so, m,
				    nextrecord);
				/* NOTREACHED */
			}
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

	while (m != NULL &&
	    (uio_resid(uio) - delayed_copy_len) > 0 && error == 0) {
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
		if (mp == NULL) {
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

				/*
				 * If this packet is an unordered packet
				 * (indicated by M_UNORDERED_DATA flag), remove
				 * the additional bytes added to the
				 * receive socket buffer size.
				 */
				if ((so->so_flags & SOF_ENABLE_MSGS) &&
				    m->m_len &&
				    (m->m_flags & M_UNORDERED_DATA) &&
				    sbreserve(&so->so_rcv,
				    so->so_rcv.sb_hiwat - m->m_len)) {
					if (so->so_msg_state->msg_uno_bytes >
					    m->m_len) {
						so->so_msg_state->
						    msg_uno_bytes -= m->m_len;
					} else {
						so->so_msg_state->
						    msg_uno_bytes = 0;
					}
					m->m_flags &= ~M_UNORDERED_DATA;
				}

				if (mp != NULL) {
					*mp = m;
					mp = &m->m_next;
					so->so_rcv.sb_mb = m = m->m_next;
					*mp = NULL;
				} else {
					if (free_list == NULL)
						free_list = m;
					else
						ml->m_next = m;
					ml = m;
					so->so_rcv.sb_mb = m = m->m_next;
					ml->m_next = NULL;
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
					/*
					 * Failed to allocate an mbuf?
					 * Adjust uio_resid back, it was
					 * adjusted down by len bytes which
					 * we didn't copy over.
					 */
					if (*mp == NULL) {
						uio_setresid(uio,
						    (uio_resid(uio) + len));
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
		while (flags & (MSG_WAITALL|MSG_WAITSTREAM) && m == NULL &&
		    (uio_resid(uio) - delayed_copy_len) > 0 &&
		    !sosendallatonce(so) && !nextrecord) {
			if (so->so_error || ((so->so_state & SS_CANTRCVMORE)
#if CONTENT_FILTER
			    && cfil_sock_data_pending(&so->so_rcv) == 0
#endif /* CONTENT_FILTER */
			    ))
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
			if (m != NULL) {
				nextrecord = m->m_nextpkt;
			}
			SB_MB_CHECK(&so->so_rcv);
		}
	}
#ifdef MORE_LOCKING_DEBUG
	if (so->so_usecount <= 1) {
		panic("%s: after big while so=%p ref=%d on socket\n",
		    __func__, so, so->so_usecount);
		/* NOTREACHED */
	}
#endif

	if (m != NULL && pr->pr_flags & PR_ATOMIC) {
		if (so->so_options & SO_DONTTRUNC) {
			flags |= MSG_RCVMORE;
		} else {
			flags |= MSG_TRUNC;
			if ((flags & MSG_PEEK) == 0)
				(void) sbdroprecord(&so->so_rcv);
		}
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
		if (m == NULL) {
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

	if (delayed_copy_len) {
		error = sodelayed_copy(so, uio, &free_list, &delayed_copy_len);
		if (error)
			goto release;
	}
	if (free_list != NULL) {
		m_freem_list(free_list);
		free_list = NULL;
	}
	if (need_event)
		postevent(so, 0, EV_OOB);

	if (orig_resid == uio_resid(uio) && orig_resid &&
	    (flags & MSG_EOR) == 0 && (so->so_state & SS_CANTRCVMORE) == 0) {
		sbunlock(&so->so_rcv, TRUE);	/* keep socket locked */
		goto restart;
	}

	if (flagsp != NULL)
		*flagsp |= flags;
release:
#ifdef MORE_LOCKING_DEBUG
	if (so->so_usecount <= 1) {
		panic("%s: release so=%p ref=%d on socket\n", __func__,
		    so, so->so_usecount);
		/* NOTREACHED */
	}
#endif
	if (delayed_copy_len)
		error = sodelayed_copy(so, uio, &free_list, &delayed_copy_len);

	if (free_list != NULL)
		m_freem_list(free_list);

	sbunlock(&so->so_rcv, FALSE);	/* will unlock socket */

	if (en_tracing) {
		KERNEL_ENERGYTRACE(kEnTrActKernSockRead, DBG_FUNC_END,
		    VM_KERNEL_ADDRPERM(so),
		    ((error == EWOULDBLOCK) ? kEnTrFlagNoWork : 0),
		    (int64_t)(orig_resid - uio_resid(uio)));
	}
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
    user_ssize_t *resid)
{
	int error = 0;
	struct mbuf *m;

	m = *free_list;

	socket_unlock(so, 0);

	while (m != NULL && error == 0) {
		error = uiomove(mtod(m, caddr_t), (int)m->m_len, uio);
		m = m->m_next;
	}
	m_freem_list(*free_list);

	*free_list = NULL;
	*resid = 0;

	socket_lock(so, 0);

	return (error);
}

static int
sodelayed_copy_list(struct socket *so, struct recv_msg_elem *msgarray,
    u_int uiocnt, struct mbuf **free_list, user_ssize_t *resid)
{
#pragma unused(so)
	int error = 0;
	struct mbuf *ml, *m;
	int i = 0;
	struct uio *auio;

	for (ml = *free_list, i = 0; ml != NULL && i < uiocnt;
	    ml = ml->m_nextpkt, i++) {
		auio = msgarray[i].uio;
		for (m = ml; m != NULL; m = m->m_next) {
			error = uiomove(mtod(m, caddr_t), m->m_len, auio);
			if (error != 0)
				goto out;
		}
	}
out:
	m_freem_list(*free_list);

	*free_list = NULL;
	*resid = 0;

	return (error);
}

int
soreceive_list(struct socket *so, struct recv_msg_elem *msgarray, u_int uiocnt,
    int *flagsp)
{
	struct mbuf *m;
	struct mbuf *nextrecord;
	struct mbuf *ml = NULL, *free_list = NULL, *free_tail = NULL;
	int error;
	user_ssize_t len, pktlen, delayed_copy_len = 0;
	struct protosw *pr = so->so_proto;
	user_ssize_t resid;
	struct proc *p = current_proc();
	struct uio *auio = NULL;
	int npkts = 0;
	int sblocked = 0;
	struct sockaddr **psa = NULL;
	struct mbuf **controlp = NULL;
	int can_delay;
	int flags;
	struct mbuf *free_others = NULL;

	KERNEL_DEBUG(DBG_FNC_SORECEIVE_LIST | DBG_FUNC_START,
	    so, uiocnt,
	    so->so_rcv.sb_cc, so->so_rcv.sb_lowat, so->so_rcv.sb_hiwat);

	/*
	 * Sanity checks:
	 * - Only supports don't wait flags
	 * - Only support datagram sockets (could be extended to raw)
	 * - Must be atomic
	 * - Protocol must support packet chains
	 * - The uio array is NULL (should we panic?)
	 */
	if (flagsp != NULL)
		flags = *flagsp;
	else
		flags = 0;
	if (flags & ~(MSG_PEEK | MSG_WAITALL | MSG_DONTWAIT | MSG_NEEDSA |
	    MSG_NBIO)) {
		printf("%s invalid flags 0x%x\n", __func__, flags);
		error = EINVAL;
		goto out;
	}
	if (so->so_type != SOCK_DGRAM) {
		error = EINVAL;
		goto out;
	}
	if (sosendallatonce(so) == 0) {
		error = EINVAL;
		goto out;
	}
	if (so->so_proto->pr_usrreqs->pru_send_list == NULL) {
		error = EPROTONOSUPPORT;
		goto out;
	}
	if (msgarray == NULL) {
		printf("%s uioarray is NULL\n", __func__);
		error = EINVAL;
		goto out;
	}
	if (uiocnt == 0) {
		printf("%s uiocnt is 0\n", __func__);
		error = EINVAL;
		goto out;
	}
	/*
	 * Sanity check on the length passed by caller as we are making 'int'
	 * comparisons
	 */
	resid = recv_msg_array_resid(msgarray, uiocnt);
	if (resid < 0 || resid > INT_MAX) {
		error = EINVAL;
		goto out;
	}

	if (!(flags & MSG_PEEK) && sorecvmincopy > 0)
		can_delay = 1;
	else
		can_delay = 0;

	socket_lock(so, 1);
	so_update_last_owner_locked(so, p);
	so_update_policy(so);

#if NECP
	so_update_necp_policy(so, NULL, NULL);
#endif /* NECP */

	/*
	 * If a recv attempt is made on a previously-accepted socket
	 * that has been marked as inactive (disconnected), reject
	 * the request.
	 */
	if (so->so_flags & SOF_DEFUNCT) {
		struct sockbuf *sb = &so->so_rcv;

		error = ENOTCONN;
		SODEFUNCTLOG(("%s[%d]: defunct so 0x%llx [%d,%d] (%d)\n",
		    __func__, proc_pid(p), (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
		    SOCK_DOM(so), SOCK_TYPE(so), error));
		/*
		 * This socket should have been disconnected and flushed
		 * prior to being returned from sodefunct(); there should
		 * be no data on its receive list, so panic otherwise.
		 */
		if (so->so_state & SS_DEFUNCT)
			sb_empty_assert(sb, __func__);
		goto release;
	}

next:
	/*
	 * The uio may be empty
	 */
	if (npkts >= uiocnt) {
		error = 0;
		goto release;
	}
restart:
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
		error = 0;
		goto release;
	}

	error = sblock(&so->so_rcv, SBLOCKWAIT(flags));
	if (error) {
		goto release;
	}
	sblocked = 1;

	m = so->so_rcv.sb_mb;
	/*
	 * Block awaiting more datagram if needed
	 */
	if (m == NULL || (((flags & MSG_DONTWAIT) == 0 &&
	    (so->so_rcv.sb_cc < so->so_rcv.sb_lowat ||
	    ((flags & MSG_WAITALL) && npkts < uiocnt))))) {
		/*
		 * Panic if we notice inconsistencies in the socket's
		 * receive list; both sb_mb and sb_cc should correctly
		 * reflect the contents of the list, otherwise we may
		 * end up with false positives during select() or poll()
		 * which could put the application in a bad state.
		 */
		SB_MB_CHECK(&so->so_rcv);

		if (so->so_error) {
			error = so->so_error;
			if ((flags & MSG_PEEK) == 0)
				so->so_error = 0;
			goto release;
		}
		if (so->so_state & SS_CANTRCVMORE) {
			goto release;
		}
		if ((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) == 0 &&
		    (so->so_proto->pr_flags & PR_CONNREQUIRED)) {
			error = ENOTCONN;
			goto release;
		}
		if ((so->so_state & SS_NBIO) ||
		    (flags & (MSG_DONTWAIT|MSG_NBIO))) {
			error = EWOULDBLOCK;
			goto release;
		}
		/*
		 * Do not block if we got some data
		 */
		if (free_list != NULL) {
			error = 0;
			goto release;
		}

		SBLASTRECORDCHK(&so->so_rcv, "soreceive sbwait 1");
		SBLASTMBUFCHK(&so->so_rcv, "soreceive sbwait 1");

		sbunlock(&so->so_rcv, TRUE);	/* keep socket locked */
		sblocked = 0;

		error = sbwait(&so->so_rcv);
		if (error) {
			goto release;
		}
		goto restart;
	}

	OSIncrementAtomicLong(&p->p_stats->p_ru.ru_msgrcv);
	SBLASTRECORDCHK(&so->so_rcv, "soreceive 1");
	SBLASTMBUFCHK(&so->so_rcv, "soreceive 1");

	/*
	 * Consume the current uio index as we have a datagram
	 */
	auio = msgarray[npkts].uio;
	resid = uio_resid(auio);
	msgarray[npkts].which |= SOCK_MSG_DATA;
	psa = (msgarray[npkts].which & SOCK_MSG_SA) ?
	    &msgarray[npkts].psa : NULL;
	controlp = (msgarray[npkts].which & SOCK_MSG_CONTROL) ?
	    &msgarray[npkts].controlp : NULL;
	npkts += 1;
	nextrecord = m->m_nextpkt;

	if ((pr->pr_flags & PR_ADDR) && m->m_type == MT_SONAME) {
		error = soreceive_addr(p, so, psa, flags, &m, &nextrecord, 1);
		if (error == ERESTART)
			goto restart;
		else if (error != 0)
			goto release;
	}

	if (m != NULL && m->m_type == MT_CONTROL) {
		error = soreceive_ctl(so, controlp, flags, &m, &nextrecord);
		if (error != 0)
			goto release;
	}

	if (m->m_pkthdr.len == 0) {
		printf("%s:%d so %llx pkt %llx type %u pktlen null\n",
		    __func__, __LINE__,
		    (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
		    (uint64_t)DEBUG_KERNEL_ADDRPERM(m),
		    m->m_type);
	}

	/*
	 * Loop to copy the mbufs of the current record
	 * Support zero length packets
	 */
	ml = NULL;
	pktlen = 0;
	while (m != NULL && (len = resid - pktlen) >= 0 && error == 0) {
		if (m->m_len == 0)
			panic("%p m_len zero", m);
		if (m->m_type == 0)
			panic("%p m_type zero", m);
		/*
		 * Clip to the residual length
		 */
		if (len > m->m_len)
			len = m->m_len;
		pktlen += len;
		/*
		 * Copy the mbufs via the uio or delay the copy
		 * Sockbuf must be consistent here (points to current mbuf,
		 * it points to next record) when we drop priority;
		 * we must note any additions to the sockbuf when we
		 * block interrupts again.
		 */
		if (len > 0 && can_delay == 0) {
			socket_unlock(so, 0);
			error = uiomove(mtod(m, caddr_t), (int)len, auio);
			socket_lock(so, 0);
			if (error)
				goto release;
		} else {
			delayed_copy_len += len;
		}

		if (len == m->m_len) {
			/*
			 * m was entirely copied
			 */
			sbfree(&so->so_rcv, m);
			nextrecord = m->m_nextpkt;
			m->m_nextpkt = NULL;

			/*
			 * Set the first packet to the head of the free list
			 */
			if (free_list == NULL)
				free_list = m;
			/*
			 * Link current packet to tail of free list
			 */
			if (ml == NULL) {
				if (free_tail != NULL)
					free_tail->m_nextpkt = m;
				free_tail = m;
			}
			/*
			 * Link current mbuf to last mbuf of current packet
			 */
			if (ml != NULL)
				ml->m_next = m;
			ml = m;

			/*
			 * Move next buf to head of socket buffer
			 */
			so->so_rcv.sb_mb = m = ml->m_next;
			ml->m_next = NULL;

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
		} else {
			/*
			 * Stop the loop on partial copy
			 */
			break;
		}
	}
#ifdef MORE_LOCKING_DEBUG
	if (so->so_usecount <= 1) {
		panic("%s: after big while so=%llx ref=%d on socket\n",
		    __func__,
		    (uint64_t)DEBUG_KERNEL_ADDRPERM(so), so->so_usecount);
		/* NOTREACHED */
	}
#endif
	/*
	 * Tell the caller we made a partial copy
	 */
	if (m != NULL) {
		if (so->so_options & SO_DONTTRUNC) {
			/*
			 * Copyout first the freelist then the partial mbuf
			 */
			socket_unlock(so, 0);
			if (delayed_copy_len)
				error = sodelayed_copy_list(so, msgarray,
				    uiocnt, &free_list, &delayed_copy_len);

			if (error == 0) {
				error = uiomove(mtod(m, caddr_t), (int)len,
				    auio);
			}
			socket_lock(so, 0);
			if (error)
				goto release;

			m->m_data += len;
			m->m_len -= len;
			so->so_rcv.sb_cc -= len;
			flags |= MSG_RCVMORE;
		} else {
			(void) sbdroprecord(&so->so_rcv);
			nextrecord = so->so_rcv.sb_mb;
			m = NULL;
			flags |= MSG_TRUNC;
		}
	}

	if (m == NULL) {
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

	/*
	 * We can continue to the next packet as long as:
	 * - We haven't exhausted the uio array
	 * - There was no error
	 * - A packet was not truncated
	 * - We can still receive more data
	 */
	if (npkts < uiocnt && error == 0 &&
	    (flags & (MSG_RCVMORE | MSG_TRUNC)) == 0 &&
	    (so->so_state & SS_CANTRCVMORE) == 0) {
		sbunlock(&so->so_rcv, TRUE);	/* keep socket locked */
		sblocked = 0;

		goto next;
	}
	if (flagsp != NULL)
		*flagsp |= flags;

release:
	/*
	 * pru_rcvd may cause more data to be received if the socket lock
	 * is dropped so we set MSG_HAVEMORE now based on what we know.
	 * That way the caller won't be surprised if it receives less data
	 * than requested.
	 */
	if ((so->so_options & SO_WANTMORE) && so->so_rcv.sb_cc > 0)
		flags |= MSG_HAVEMORE;

	if (pr->pr_flags & PR_WANTRCVD && so->so_pcb)
		(*pr->pr_usrreqs->pru_rcvd)(so, flags);

	if (sblocked)
		sbunlock(&so->so_rcv, FALSE);	/* will unlock socket */
	else
		socket_unlock(so, 1);

	if (delayed_copy_len)
		error = sodelayed_copy_list(so, msgarray, uiocnt,
		    &free_list, &delayed_copy_len);
out:
	/*
	 * Amortize the cost of freeing the mbufs
	 */
	if (free_list != NULL)
		m_freem_list(free_list);
	if (free_others != NULL)
		m_freem_list(free_others);

	KERNEL_DEBUG(DBG_FNC_SORECEIVE_LIST | DBG_FUNC_END, error,
	    0, 0, 0, 0);
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

	KERNEL_DEBUG(DBG_FNC_SOSHUTDOWN | DBG_FUNC_START, how, 0, 0, 0, 0);

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

	KERNEL_DEBUG(DBG_FNC_SOSHUTDOWN | DBG_FUNC_END, how, error, 0, 0, 0);

	return (error);
}

int
soshutdownlock_final(struct socket *so, int how)
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
	KERNEL_DEBUG(DBG_FNC_SOSHUTDOWN, how, 1, 0, 0, 0);
	return (error);
}

int
soshutdownlock(struct socket *so, int how)
{
	int error = 0;

#if CONTENT_FILTER
	/*
	 * A content filter may delay the actual shutdown until it
	 * has processed the pending data
	 */
	if (so->so_flags & SOF_CONTENT_FILTER) {
		error = cfil_sock_shutdown(so, &how);
		if (error == EJUSTRETURN) {
			error = 0;
			goto done;
		} else if (error != 0) {
			goto done;
		}
	}
#endif /* CONTENT_FILTER */

	error = soshutdownlock_final(so, how);

done:
	return (error);
}

void
sowflush(struct socket *so)
{
	struct sockbuf *sb = &so->so_snd;
#ifdef notyet
	lck_mtx_t *mutex_held;
	/*
	 * XXX: This code is currently commented out, because we may get here
	 * as part of sofreelastref(), and at that time, pr_getlock() may no
	 * longer be able to return us the lock; this will be fixed in future.
	 */
	if (so->so_proto->pr_getlock != NULL)
		mutex_held = (*so->so_proto->pr_getlock)(so, 0);
	else
		mutex_held = so->so_proto->pr_domain->dom_mtx;

	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
#endif /* notyet */

	/*
	 * Obtain lock on the socket buffer (SB_LOCK).  This is required
	 * to prevent the socket buffer from being unexpectedly altered
	 * while it is used by another thread in socket send/receive.
	 *
	 * sblock() must not fail here, hence the assertion.
	 */
	(void) sblock(sb, SBL_WAIT | SBL_NOINTR | SBL_IGNDEFUNCT);
	VERIFY(sb->sb_flags & SB_LOCK);

	sb->sb_flags		&= ~(SB_SEL|SB_UPCALL);
	sb->sb_flags		|= SB_DROP;
	sb->sb_upcall		= NULL;
	sb->sb_upcallarg	= NULL;

	sbunlock(sb, TRUE);	/* keep socket locked */

	selthreadclear(&sb->sb_sel);
	sbrelease(sb);
}

void
sorflush(struct socket *so)
{
	struct sockbuf *sb = &so->so_rcv;
	struct protosw *pr = so->so_proto;
	struct sockbuf asb;
#ifdef notyet
	lck_mtx_t *mutex_held;
	/*
	 * XXX: This code is currently commented out, because we may get here
	 * as part of sofreelastref(), and at that time, pr_getlock() may no
	 * longer be able to return us the lock; this will be fixed in future.
	 */
	if (so->so_proto->pr_getlock != NULL)
		mutex_held = (*so->so_proto->pr_getlock)(so, 0);
	else
		mutex_held = so->so_proto->pr_domain->dom_mtx;

	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
#endif /* notyet */

	sflt_notify(so, sock_evt_flush_read, NULL);

	socantrcvmore(so);

	/*
	 * Obtain lock on the socket buffer (SB_LOCK).  This is required
	 * to prevent the socket buffer from being unexpectedly altered
	 * while it is used by another thread in socket send/receive.
	 *
	 * sblock() must not fail here, hence the assertion.
	 */
	(void) sblock(sb, SBL_WAIT | SBL_NOINTR | SBL_IGNDEFUNCT);
	VERIFY(sb->sb_flags & SB_LOCK);

	/*
	 * Copy only the relevant fields from "sb" to "asb" which we
	 * need for sbrelease() to function.  In particular, skip
	 * sb_sel as it contains the wait queue linkage, which would
	 * wreak havoc if we were to issue selthreadclear() on "asb".
	 * Make sure to not carry over SB_LOCK in "asb", as we need
	 * to acquire it later as part of sbrelease().
	 */
	bzero(&asb, sizeof (asb));
	asb.sb_cc		= sb->sb_cc;
	asb.sb_hiwat		= sb->sb_hiwat;
	asb.sb_mbcnt		= sb->sb_mbcnt;
	asb.sb_mbmax		= sb->sb_mbmax;
	asb.sb_ctl		= sb->sb_ctl;
	asb.sb_lowat		= sb->sb_lowat;
	asb.sb_mb		= sb->sb_mb;
	asb.sb_mbtail		= sb->sb_mbtail;
	asb.sb_lastrecord	= sb->sb_lastrecord;
	asb.sb_so		= sb->sb_so;
	asb.sb_flags		= sb->sb_flags;
	asb.sb_flags		&= ~(SB_LOCK|SB_SEL|SB_KNOTE|SB_UPCALL);
	asb.sb_flags		|= SB_DROP;

	/*
	 * Ideally we'd bzero() these and preserve the ones we need;
	 * but to do that we'd need to shuffle things around in the
	 * sockbuf, and we can't do it now because there are KEXTS
	 * that are directly referring to the socket structure.
	 *
	 * Setting SB_DROP acts as a barrier to prevent further appends.
	 * Clearing SB_SEL is done for selthreadclear() below.
	 */
	sb->sb_cc		= 0;
	sb->sb_hiwat		= 0;
	sb->sb_mbcnt		= 0;
	sb->sb_mbmax		= 0;
	sb->sb_ctl		= 0;
	sb->sb_lowat		= 0;
	sb->sb_mb		= NULL;
	sb->sb_mbtail		= NULL;
	sb->sb_lastrecord	= NULL;
	sb->sb_timeo.tv_sec	= 0;
	sb->sb_timeo.tv_usec	= 0;
	sb->sb_upcall		= NULL;
	sb->sb_upcallarg	= NULL;
	sb->sb_flags		&= ~(SB_SEL|SB_UPCALL);
	sb->sb_flags		|= SB_DROP;

	sbunlock(sb, TRUE);	/* keep socket locked */

	/*
	 * Note that selthreadclear() is called on the original "sb" and
	 * not the local "asb" because of the way wait queue linkage is
	 * implemented.  Given that selwakeup() may be triggered, SB_SEL
	 * should no longer be set (cleared above.)
	 */
	selthreadclear(&sb->sb_sel);

	if ((pr->pr_flags & PR_RIGHTS) && pr->pr_domain->dom_dispose)
		(*pr->pr_domain->dom_dispose)(asb.sb_mb);

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
sooptcopyin_timeval(struct sockopt *sopt, struct timeval *tv_p)
{
	int			error;

	if (proc_is64bit(sopt->sopt_p)) {
		struct user64_timeval	tv64;

		if (sopt->sopt_valsize < sizeof (tv64))
			return (EINVAL);

		sopt->sopt_valsize = sizeof (tv64);
		if (sopt->sopt_p != kernproc) {
			error = copyin(sopt->sopt_val, &tv64, sizeof (tv64));
			if (error != 0)
				return (error);
		} else {
			bcopy(CAST_DOWN(caddr_t, sopt->sopt_val), &tv64,
			    sizeof (tv64));
		}
		if (tv64.tv_sec < 0 || tv64.tv_sec > LONG_MAX ||
		    tv64.tv_usec < 0 || tv64.tv_usec >= 1000000)
			return (EDOM);

		tv_p->tv_sec = tv64.tv_sec;
		tv_p->tv_usec = tv64.tv_usec;
	} else {
		struct user32_timeval	tv32;

		if (sopt->sopt_valsize < sizeof (tv32))
			return (EINVAL);

		sopt->sopt_valsize = sizeof (tv32);
		if (sopt->sopt_p != kernproc) {
			error = copyin(sopt->sopt_val, &tv32, sizeof (tv32));
			if (error != 0) {
				return (error);
			}
		} else {
			bcopy(CAST_DOWN(caddr_t, sopt->sopt_val), &tv32,
			    sizeof (tv32));
		}
#ifndef __LP64__
		/*
		 * K64todo "comparison is always false due to
		 * limited range of data type"
		 */
		if (tv32.tv_sec < 0 || tv32.tv_sec > LONG_MAX ||
		    tv32.tv_usec < 0 || tv32.tv_usec >= 1000000)
			return (EDOM);
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
sosetoptlock(struct socket *so, struct sockopt *sopt, int dolock)
{
	int	error, optval;
	struct	linger l;
	struct	timeval tv;
#if CONFIG_MACF_SOCKET
	struct mac extmac;
#endif /* MAC_SOCKET */

	if (sopt->sopt_dir != SOPT_SET)
		sopt->sopt_dir = SOPT_SET;

	if (dolock)
		socket_lock(so, 1);

	if ((so->so_state & (SS_CANTRCVMORE | SS_CANTSENDMORE)) ==
	    (SS_CANTRCVMORE | SS_CANTSENDMORE) &&
	    (so->so_flags & SOF_NPX_SETOPTSHUT) == 0) {
		/* the socket has been shutdown, no more sockopt's */
		error = EINVAL;
		goto out;
	}

	error = sflt_setsockopt(so, sopt);
	if (error != 0) {
		if (error == EJUSTRETURN)
			error = 0;
		goto out;
	}

	if (sopt->sopt_level != SOL_SOCKET) {
		if (so->so_proto != NULL &&
		    so->so_proto->pr_ctloutput != NULL) {
			error = (*so->so_proto->pr_ctloutput)(so, sopt);
			goto out;
		}
		error = ENOPROTOOPT;
	} else {
		/*
		 * Allow socket-level (SOL_SOCKET) options to be filtered by
		 * the protocol layer, if needed.  A zero value returned from
		 * the handler means use default socket-level processing as
		 * done by the rest of this routine.  Otherwise, any other
		 * return value indicates that the option is unsupported.
		 */
		if (so->so_proto != NULL && (error = so->so_proto->pr_usrreqs->
		    pru_socheckopt(so, sopt)) != 0)
			goto out;

		error = 0;
		switch (sopt->sopt_name) {
		case SO_LINGER:
		case SO_LINGER_SEC:
			error = sooptcopyin(sopt, &l, sizeof (l), sizeof (l));
			if (error != 0)
				goto out;

			so->so_linger = (sopt->sopt_name == SO_LINGER) ?
			    l.l_linger : l.l_linger * hz;
			if (l.l_onoff != 0)
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
		case SO_DONTTRUNC:
		case SO_WANTMORE:
		case SO_WANTOOBFLAG:
		case SO_NOWAKEFROMSLEEP:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error != 0)
				goto out;
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
			if (error != 0)
				goto out;

			/*
			 * Values < 1 make no sense for any of these
			 * options, so disallow them.
			 */
			if (optval < 1) {
				error = EINVAL;
				goto out;
			}

			switch (sopt->sopt_name) {
			case SO_SNDBUF:
			case SO_RCVBUF: {
				struct sockbuf *sb =
				    (sopt->sopt_name == SO_SNDBUF) ?
				    &so->so_snd : &so->so_rcv;
				if (sbreserve(sb, (u_int32_t)optval) == 0) {
					error = ENOBUFS;
					goto out;
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
			case SO_SNDLOWAT: {
				int space = sbspace(&so->so_snd);
				u_int32_t hiwat = so->so_snd.sb_hiwat;

				if (so->so_snd.sb_flags & SB_UNIX) {
					struct unpcb *unp =
					    (struct unpcb *)(so->so_pcb);
					if (unp != NULL &&
					    unp->unp_conn != NULL) {
						hiwat += unp->unp_conn->unp_cc;
					}
				}

				so->so_snd.sb_lowat =
				    (optval > hiwat) ?
				    hiwat : optval;

				if (space >= so->so_snd.sb_lowat) {
					sowwakeup(so);
				}
				break;
			}
			case SO_RCVLOWAT: {
				int64_t data_len;
				so->so_rcv.sb_lowat =
				    (optval > so->so_rcv.sb_hiwat) ?
				    so->so_rcv.sb_hiwat : optval;
				data_len = so->so_rcv.sb_cc
				    - so->so_rcv.sb_ctl;
				if (data_len >= so->so_rcv.sb_lowat)
				    sorwakeup(so);
				break;
			}
			}
			break;

		case SO_SNDTIMEO:
		case SO_RCVTIMEO:
			error = sooptcopyin_timeval(sopt, &tv);
			if (error != 0)
				goto out;

			switch (sopt->sopt_name) {
			case SO_SNDTIMEO:
				so->so_snd.sb_timeo = tv;
				break;
			case SO_RCVTIMEO:
				so->so_rcv.sb_timeo = tv;
				break;
			}
			break;

		case SO_NKE: {
			struct so_nke nke;

			error = sooptcopyin(sopt, &nke, sizeof (nke),
			    sizeof (nke));
			if (error != 0)
				goto out;

			error = sflt_attach_internal(so, nke.nke_handle);
			break;
		}

		case SO_NOSIGPIPE:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error != 0)
				goto out;
			if (optval != 0)
				so->so_flags |= SOF_NOSIGPIPE;
			else
				so->so_flags &= ~SOF_NOSIGPIPE;
			break;

		case SO_NOADDRERR:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error != 0)
				goto out;
			if (optval != 0)
				so->so_flags |= SOF_NOADDRAVAIL;
			else
				so->so_flags &= ~SOF_NOADDRAVAIL;
			break;

		case SO_REUSESHAREUID:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error != 0)
				goto out;
			if (optval != 0)
				so->so_flags |= SOF_REUSESHAREUID;
			else
				so->so_flags &= ~SOF_REUSESHAREUID;
			break;

		case SO_NOTIFYCONFLICT:
			if (kauth_cred_issuser(kauth_cred_get()) == 0) {
				error = EPERM;
				goto out;
			}
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error != 0)
				goto out;
			if (optval != 0)
				so->so_flags |= SOF_NOTIFYCONFLICT;
			else
				so->so_flags &= ~SOF_NOTIFYCONFLICT;
			break;

		case SO_RESTRICTIONS:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error != 0)
				goto out;

			error = so_set_restrictions(so, optval);
			break;

		case SO_AWDL_UNRESTRICTED:
			if (SOCK_DOM(so) != PF_INET &&
			    SOCK_DOM(so) != PF_INET6) {
				error = EOPNOTSUPP;
				goto out;
			}
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error != 0)
				goto out;
			if (optval != 0) {
				kauth_cred_t cred =  NULL;
				proc_t ep = PROC_NULL;

				if (so->so_flags & SOF_DELEGATED) {
					ep = proc_find(so->e_pid);
					if (ep)
						cred = kauth_cred_proc_ref(ep);
				}
				error = priv_check_cred(
				    cred ? cred : so->so_cred,
				    PRIV_NET_RESTRICTED_AWDL, 0);
				if (error == 0)
					inp_set_awdl_unrestricted(
					    sotoinpcb(so));
				if (cred)
					kauth_cred_unref(&cred);
				if (ep != PROC_NULL)
					proc_rele(ep);
			} else
				inp_clear_awdl_unrestricted(sotoinpcb(so));
			break;

		case SO_LABEL:
#if CONFIG_MACF_SOCKET
			if ((error = sooptcopyin(sopt, &extmac, sizeof (extmac),
			    sizeof (extmac))) != 0)
				goto out;

			error = mac_setsockopt_label(proc_ucred(sopt->sopt_p),
			    so, &extmac);
#else
			error = EOPNOTSUPP;
#endif /* MAC_SOCKET */
			break;

		case SO_UPCALLCLOSEWAIT:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error != 0)
				goto out;
			if (optval != 0)
				so->so_flags |= SOF_UPCALLCLOSEWAIT;
			else
				so->so_flags &= ~SOF_UPCALLCLOSEWAIT;
			break;

		case SO_RANDOMPORT:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error != 0)
				goto out;
			if (optval != 0)
				so->so_flags |= SOF_BINDRANDOMPORT;
			else
				so->so_flags &= ~SOF_BINDRANDOMPORT;
			break;

		case SO_NP_EXTENSIONS: {
			struct so_np_extensions sonpx;

			error = sooptcopyin(sopt, &sonpx, sizeof (sonpx),
			    sizeof (sonpx));
			if (error != 0)
				goto out;
			if (sonpx.npx_mask & ~SONPX_MASK_VALID) {
				error = EINVAL;
				goto out;
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
			if (error != 0)
				goto out;
			error = so_set_traffic_class(so, optval);
			if (error != 0)
				goto out;
			break;
		}

		case SO_RECV_TRAFFIC_CLASS: {
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error != 0)
				goto out;
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
			if (error != 0)
				goto out;
			error = so_set_tcdbg(so, &so_tcdbg);
			if (error != 0)
				goto out;
			break;
		}

		case SO_PRIVILEGED_TRAFFIC_CLASS:
			error = priv_check_cred(kauth_cred_get(),
			    PRIV_NET_PRIVILEGED_TRAFFIC_CLASS, 0);
			if (error != 0)
				goto out;
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error != 0)
				goto out;
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
				goto out;
			}
			/*
			 * Any process can set SO_DEFUNCTOK (clear
			 * SOF_NODEFUNCT), but only root can clear
			 * SO_DEFUNCTOK (set SOF_NODEFUNCT).
			 */
			if (optval == 0 &&
			    kauth_cred_issuser(kauth_cred_get()) == 0) {
				error = EPERM;
				goto out;
			}
			if (optval)
				so->so_flags &= ~SOF_NODEFUNCT;
			else
				so->so_flags |= SOF_NODEFUNCT;

			if (SOCK_DOM(so) == PF_INET ||
			    SOCK_DOM(so) == PF_INET6) {
				char s[MAX_IPv6_STR_LEN];
				char d[MAX_IPv6_STR_LEN];
				struct inpcb *inp = sotoinpcb(so);

				SODEFUNCTLOG(("%s[%d]: so 0x%llx [%s %s:%d -> "
				    "%s:%d] is now marked as %seligible for "
				    "defunct\n", __func__, proc_selfpid(),
				    (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
				    (SOCK_TYPE(so) == SOCK_STREAM) ?
				    "TCP" : "UDP", inet_ntop(SOCK_DOM(so),
				    ((SOCK_DOM(so) == PF_INET) ?
				    (void *)&inp->inp_laddr.s_addr :
				    (void *)&inp->in6p_laddr), s, sizeof (s)),
				    ntohs(inp->in6p_lport),
				    inet_ntop(SOCK_DOM(so),
				    (SOCK_DOM(so) == PF_INET) ?
				    (void *)&inp->inp_faddr.s_addr :
				    (void *)&inp->in6p_faddr, d, sizeof (d)),
				    ntohs(inp->in6p_fport),
				    (so->so_flags & SOF_NODEFUNCT) ?
				    "not " : ""));
			} else {
				SODEFUNCTLOG(("%s[%d]: so 0x%llx [%d,%d] is "
				    "now marked as %seligible for defunct\n",
				    __func__, proc_selfpid(),
				    (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
				    SOCK_DOM(so), SOCK_TYPE(so),
				    (so->so_flags & SOF_NODEFUNCT) ?
				    "not " : ""));
			}
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

		case SO_TRAFFIC_MGT_BACKGROUND: {
			/* This option is handled by lower layer(s) */
			error = 0;
			break;
		}

#if FLOW_DIVERT
		case SO_FLOW_DIVERT_TOKEN:
			error = flow_divert_token_set(so, sopt);
			break;
#endif	/* FLOW_DIVERT */


		case SO_DELEGATED:
			if ((error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval))) != 0)
				break;

			error = so_set_effective_pid(so, optval, sopt->sopt_p);
			break;

		case SO_DELEGATED_UUID: {
			uuid_t euuid;

			if ((error = sooptcopyin(sopt, &euuid, sizeof (euuid),
			    sizeof (euuid))) != 0)
				break;

			error = so_set_effective_uuid(so, euuid, sopt->sopt_p);
			break;
		}

#if NECP
		case SO_NECP_ATTRIBUTES:
			error = necp_set_socket_attributes(so, sopt);
			break;
#endif /* NECP */

#if MPTCP
		case SO_MPTCP_FASTJOIN:
			if (!((so->so_flags & SOF_MP_SUBFLOW) ||
			    ((SOCK_CHECK_DOM(so, PF_MULTIPATH)) &&
			    (SOCK_CHECK_PROTO(so, IPPROTO_TCP))))) {
				error = ENOPROTOOPT;
				break;
			}

			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error != 0)
				goto out;
			if (optval == 0)
				so->so_flags &= ~SOF_MPTCP_FASTJOIN;
			else
				so->so_flags |= SOF_MPTCP_FASTJOIN;
			break;
#endif /* MPTCP */

		case SO_EXTENDED_BK_IDLE:
			error = sooptcopyin(sopt, &optval, sizeof (optval),
			    sizeof (optval));
			if (error == 0)
				error = so_set_extended_bk_idle(so, optval);
			break;

		case SO_MARK_CELLFALLBACK:
			error = sooptcopyin(sopt, &optval, sizeof(optval),
			    sizeof(optval));
			if (error != 0)
				goto out;
			if (optval < 0) {
				error = EINVAL;
				goto out;
			}
			if (optval == 0)
				so->so_flags1 &= ~SOF1_CELLFALLBACK;
			else
				so->so_flags1 |= SOF1_CELLFALLBACK;
			break;
		default:
			error = ENOPROTOOPT;
			break;
		}
		if (error == 0 && so->so_proto != NULL &&
		    so->so_proto->pr_ctloutput != NULL) {
			(void) so->so_proto->pr_ctloutput(so, sopt);
		}
	}
out:
	if (dolock)
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
sooptcopyout_timeval(struct sockopt *sopt, const struct timeval *tv_p)
{
	int			error;
	size_t			len;
	struct user64_timeval	tv64;
	struct user32_timeval	tv32;
	const void *		val;
	size_t			valsize;

	error = 0;
	if (proc_is64bit(sopt->sopt_p)) {
		len = sizeof (tv64);
		tv64.tv_sec = tv_p->tv_sec;
		tv64.tv_usec = tv_p->tv_usec;
		val = &tv64;
	} else {
		len = sizeof (tv32);
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
sogetoptlock(struct socket *so, struct sockopt *sopt, int dolock)
{
	int	error, optval;
	struct	linger l;
	struct	timeval tv;
#if CONFIG_MACF_SOCKET
	struct mac extmac;
#endif /* MAC_SOCKET */

	if (sopt->sopt_dir != SOPT_GET)
		sopt->sopt_dir = SOPT_GET;

	if (dolock)
		socket_lock(so, 1);

	error = sflt_getsockopt(so, sopt);
	if (error != 0) {
		if (error == EJUSTRETURN)
			error = 0;
		goto out;
	}

	if (sopt->sopt_level != SOL_SOCKET) {
		if (so->so_proto != NULL &&
		    so->so_proto->pr_ctloutput != NULL) {
			error = (*so->so_proto->pr_ctloutput)(so, sopt);
			goto out;
		}
		error = ENOPROTOOPT;
	} else {
		/*
		 * Allow socket-level (SOL_SOCKET) options to be filtered by
		 * the protocol layer, if needed.  A zero value returned from
		 * the handler means use default socket-level processing as
		 * done by the rest of this routine.  Otherwise, any other
		 * return value indicates that the option is unsupported.
		 */
		if (so->so_proto != NULL && (error = so->so_proto->pr_usrreqs->
		    pru_socheckopt(so, sopt)) != 0)
			goto out;

		error = 0;
		switch (sopt->sopt_name) {
		case SO_LINGER:
		case SO_LINGER_SEC:
			l.l_onoff = ((so->so_options & SO_LINGER) ? 1 : 0);
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
		case SO_DONTTRUNC:
		case SO_WANTMORE:
		case SO_WANTOOBFLAG:
		case SO_NOWAKEFROMSLEEP:
			optval = so->so_options & sopt->sopt_name;
integer:
			error = sooptcopyout(sopt, &optval, sizeof (optval));
			break;

		case SO_TYPE:
			optval = so->so_type;
			goto integer;

		case SO_NREAD:
			if (so->so_proto->pr_flags & PR_ATOMIC) {
				int pkt_total;
				struct mbuf *m1;

				pkt_total = 0;
				m1 = so->so_rcv.sb_mb;
				while (m1 != NULL) {
					if (m1->m_type == MT_DATA ||
					    m1->m_type == MT_HEADER ||
					    m1->m_type == MT_OOBDATA)
						pkt_total += m1->m_len;
					m1 = m1->m_next;
				}
				optval = pkt_total;
			} else {
				optval = so->so_rcv.sb_cc - so->so_rcv.sb_ctl;
			}
			goto integer;

		case SO_NUMRCVPKT:
			if (so->so_proto->pr_flags & PR_ATOMIC) {
				int cnt = 0;
				struct mbuf *m1;

				m1 = so->so_rcv.sb_mb;
				while (m1 != NULL) {
					if (m1->m_type == MT_DATA ||
					    m1->m_type == MT_HEADER ||
					    m1->m_type == MT_OOBDATA)
						cnt += 1;
					m1 = m1->m_nextpkt;
				}
				optval = cnt;
				goto integer;
			} else {
				error = EINVAL;
				break;
			}

		case SO_NWRITE:
			optval = so->so_snd.sb_cc;
			goto integer;

		case SO_ERROR:
			optval = so->so_error;
			so->so_error = 0;
			goto integer;

		case SO_SNDBUF: {
			u_int32_t hiwat = so->so_snd.sb_hiwat;

			if (so->so_snd.sb_flags & SB_UNIX) {
				struct unpcb *unp =
				    (struct unpcb *)(so->so_pcb);
				if (unp != NULL && unp->unp_conn != NULL) {
					hiwat += unp->unp_conn->unp_cc;
				}
			}

			optval = hiwat;
			goto integer;
		}
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


		case SO_NOTIFYCONFLICT:
			optval = (so->so_flags & SOF_NOTIFYCONFLICT);
			goto integer;

		case SO_RESTRICTIONS:
			optval = so_get_restrictions(so);
			goto integer;

		case SO_AWDL_UNRESTRICTED:
			if (SOCK_DOM(so) == PF_INET ||
			    SOCK_DOM(so) == PF_INET6) {
				optval = inp_get_awdl_unrestricted(
				    sotoinpcb(so));
				goto integer;
			} else
				error = EOPNOTSUPP;
			break;

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

			sonpx.npx_flags = (so->so_flags & SOF_NPX_SETOPTSHUT) ?
			    SONPX_SETOPTSHUT : 0;
			sonpx.npx_mask = SONPX_MASK_VALID;

			error = sooptcopyout(sopt, &sonpx,
			    sizeof (struct so_np_extensions));
			break;
		}

		case SO_TRAFFIC_CLASS:
			optval = so->so_traffic_class;
			goto integer;

		case SO_RECV_TRAFFIC_CLASS:
			optval = (so->so_flags & SOF_RECV_TRAFFIC_CLASS);
			goto integer;

		case SO_TRAFFIC_CLASS_STATS:
			error = sooptcopyout(sopt, &so->so_tc_stats,
			    sizeof (so->so_tc_stats));
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

		case SO_TRAFFIC_MGT_BACKGROUND:
			/* This option is handled by lower layer(s) */
			if (so->so_proto != NULL &&
			    so->so_proto->pr_ctloutput != NULL) {
				(void) so->so_proto->pr_ctloutput(so, sopt);
			}
			break;

#if FLOW_DIVERT
		case SO_FLOW_DIVERT_TOKEN:
			error = flow_divert_token_get(so, sopt);
			break;
#endif	/* FLOW_DIVERT */

#if NECP
		case SO_NECP_ATTRIBUTES:
			error = necp_get_socket_attributes(so, sopt);
			break;
#endif /* NECP */

#if CONTENT_FILTER
		case SO_CFIL_SOCK_ID: {
			cfil_sock_id_t sock_id;

			sock_id = cfil_sock_id_from_socket(so);

			error = sooptcopyout(sopt, &sock_id,
				sizeof(cfil_sock_id_t));
			break;
		}
#endif	/* CONTENT_FILTER */

#if MPTCP
		case SO_MPTCP_FASTJOIN:
			if (!((so->so_flags & SOF_MP_SUBFLOW) ||
			    ((SOCK_CHECK_DOM(so, PF_MULTIPATH)) &&
			    (SOCK_CHECK_PROTO(so, IPPROTO_TCP))))) {
				error = ENOPROTOOPT;
				break;
			}
			optval = (so->so_flags & SOF_MPTCP_FASTJOIN);
			/* Fixed along with rdar://19391339 */
			goto integer;
#endif /* MPTCP */

		case SO_EXTENDED_BK_IDLE:
			optval = (so->so_flags1 & SOF1_EXTEND_BK_IDLE_WANTED);
			goto integer;
		case SO_MARK_CELLFALLBACK:
			optval = ((so->so_flags1 & SOF1_CELLFALLBACK) > 0)
			    ? 1 : 0;
			goto integer;
		default:
			error = ENOPROTOOPT;
			break;
		}
	}
out:
	if (dolock)
		socket_unlock(so, 1);
	return (error);
}

/*
 * The size limits on our soopt_getm is different from that on FreeBSD.
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
	if (m == NULL)
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
		if (m == NULL) {
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
	/* should be allocated enoughly at ip6_sooptmcopyin() */
	if (m != NULL) {
		panic("soopt_mcopyin");
		/* NOTREACHED */
	}
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
sopoll(struct socket *so, int events, kauth_cred_t cred, void * wql)
{
#pragma unused(cred)
	struct proc *p = current_proc();
	int revents = 0;

	socket_lock(so, 1);
	so_update_last_owner_locked(so, PROC_NULL);
	so_update_policy(so);

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
soo_kqfilter(struct fileproc *fp, struct knote *kn, vfs_context_t ctx)
{
#pragma unused(fp)
#if !CONFIG_MACF_SOCKET
#pragma unused(ctx)
#endif /* MAC_SOCKET */
	struct socket *so = (struct socket *)kn->kn_fp->f_fglob->fg_data;
	struct klist *skl;

	socket_lock(so, 1);
	so_update_last_owner_locked(so, PROC_NULL);
	so_update_policy(so);

#if CONFIG_MACF_SOCKET
	if (mac_socket_check_kqfilter(proc_ucred(vfs_context_proc(ctx)),
	    kn, so) != 0) {
		socket_unlock(so, 1);
		return (1);
	}
#endif /* MAC_SOCKET */

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &soread_filtops;
		/*
		 * If the caller explicitly asked for OOB results (e.g. poll()),
		 * save that off in the hookid field and reserve the kn_flags
		 * EV_OOBAND bit for output only.
		 */
		if (kn->kn_flags & EV_OOBAND) {
			kn->kn_flags &= ~EV_OOBAND;
			kn->kn_hookid = EV_OOBAND;
		} else {
			kn->kn_hookid = 0;
		}
		skl = &so->so_rcv.sb_sel.si_note;
		break;
	case EVFILT_WRITE:
		kn->kn_fop = &sowrite_filtops;
		skl = &so->so_snd.sb_sel.si_note;
		break;
	case EVFILT_SOCK:
		kn->kn_fop = &sock_filtops;
		skl = &so->so_klist;
		kn->kn_hookid = 0;
		kn->kn_status |= KN_TOUCH;
		break;
	default:
		socket_unlock(so, 1);
		return (1);
	}

	if (KNOTE_ATTACH(skl, kn)) {
		switch (kn->kn_filter) {
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

		/*
		 * Radar 6615193 handle the listen case dynamically
		 * for kqueue read filter. This allows to call listen()
		 * after registering the kqueue EVFILT_READ.
		 */

		kn->kn_data = so->so_qlen;
		isempty = ! TAILQ_EMPTY(&so->so_comp);

		if ((hint & SO_FILT_HINT_LOCKED) == 0)
			socket_unlock(so, 1);

		return (isempty);
	}

	/* socket isn't a listener */
	/*
	 * NOTE_LOWAT specifies new low water mark in data, i.e.
	 * the bytes of protocol data. We therefore exclude any
	 * control bytes.
	 */
	kn->kn_data = so->so_rcv.sb_cc - so->so_rcv.sb_ctl;

	/*
	 * Clear out EV_OOBAND that filt_soread may have set in the
	 * past.
	 */
	kn->kn_flags &= ~EV_OOBAND;
	if ((so->so_oobmark) || (so->so_state & SS_RCVATMARK)) {
		kn->kn_flags |= EV_OOBAND;
		/*
		 * If caller registered explicit interest in OOB data,
		 * return immediately (data == amount beyond mark, for
		 * legacy reasons - that should be changed later).
		 */
		if (kn->kn_hookid == EV_OOBAND) {
			/*
			 * When so_state is SS_RCVATMARK, so_oobmark
			 * is 0.
			 */
			kn->kn_data -= so->so_oobmark;
			if ((hint & SO_FILT_HINT_LOCKED) == 0)
				socket_unlock(so, 1);
			return (1);
		}
	}

	if ((so->so_state & SS_CANTRCVMORE)
#if CONTENT_FILTER
	    && cfil_sock_data_pending(&so->so_rcv) == 0
#endif /* CONTENT_FILTER */
	   ) {
		kn->kn_flags |= EV_EOF;
		kn->kn_fflags = so->so_error;
		if ((hint & SO_FILT_HINT_LOCKED) == 0)
			socket_unlock(so, 1);
		return (1);
	}

	if (so->so_error) {	/* temporary udp error */
		if ((hint & SO_FILT_HINT_LOCKED) == 0)
			socket_unlock(so, 1);
		return (1);
	}

	int64_t	lowwat = so->so_rcv.sb_lowat;
	/*
	 * Ensure that when NOTE_LOWAT is used, the derived
	 * low water mark is bounded by socket's rcv buf's
	 * high and low water mark values.
	 */
	if (kn->kn_sfflags & NOTE_LOWAT) {
		if (kn->kn_sdata > so->so_rcv.sb_hiwat)
			lowwat = so->so_rcv.sb_hiwat;
		else if (kn->kn_sdata > lowwat)
			lowwat = kn->kn_sdata;
	}

	if ((hint & SO_FILT_HINT_LOCKED) == 0)
		socket_unlock(so, 1);

	/*
	 * The order below is important. Since NOTE_LOWAT
	 * overrides sb_lowat, check for NOTE_LOWAT case
	 * first.
	 */
	if (kn->kn_sfflags & NOTE_LOWAT)
		return (kn->kn_data >= lowwat);

	return (so->so_rcv.sb_cc >= lowwat);
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
	if ((SOCK_DOM(so) == PF_INET || SOCK_DOM(so) == PF_INET6) &&
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
	if (!socanwrite(so)) {
		ret = 0;
		goto out;
	}
	if (so->so_flags1 & SOF1_PRECONNECT_DATA) {
		ret = 1;
		goto out;
	}
	int64_t	lowwat = so->so_snd.sb_lowat;
	if (kn->kn_sfflags & NOTE_LOWAT) {
		if (kn->kn_sdata > so->so_snd.sb_hiwat)
			lowwat = so->so_snd.sb_hiwat;
		else if (kn->kn_sdata > lowwat)
			lowwat = kn->kn_sdata;
	}
	if (kn->kn_data >= lowwat) {
		if (so->so_flags & SOF_NOTSENT_LOWAT) {
			if ((SOCK_DOM(so) == PF_INET
			    || SOCK_DOM(so) == PF_INET6)
			    && so->so_type == SOCK_STREAM) {
				ret = tcp_notsent_lowat_check(so);
			}
#if MPTCP
			else if ((SOCK_DOM(so) == PF_MULTIPATH) &&
			    (SOCK_PROTO(so) == IPPROTO_TCP)) {
				ret = mptcp_notsent_lowat_check(so);
			}
#endif
			else {
				ret = 1;
				goto out;
			}
		} else {
			ret = 1;
		}
	}
	if (so_wait_for_if_feedback(so))
		ret = 0;
out:
	if ((hint & SO_FILT_HINT_LOCKED) == 0)
		socket_unlock(so, 1);
	return (ret);
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
	long ev_hint = (hint & SO_FILT_HINT_EV);
	uint32_t level_trigger = 0;

	if ((hint & SO_FILT_HINT_LOCKED) == 0) {
		socket_lock(so, 1);
		locked = 1;
	}

	if (ev_hint & SO_FILT_HINT_CONNRESET) {
		kn->kn_fflags |= NOTE_CONNRESET;
	}
	if (ev_hint & SO_FILT_HINT_TIMEOUT) {
		kn->kn_fflags |= NOTE_TIMEOUT;
	}
	if (ev_hint & SO_FILT_HINT_NOSRCADDR) {
		kn->kn_fflags |= NOTE_NOSRCADDR;
	}
	if (ev_hint & SO_FILT_HINT_IFDENIED) {
		kn->kn_fflags |= NOTE_IFDENIED;
	}
	if (ev_hint & SO_FILT_HINT_KEEPALIVE) {
		kn->kn_fflags |= NOTE_KEEPALIVE;
	}
	if (ev_hint & SO_FILT_HINT_ADAPTIVE_WTIMO) {
		kn->kn_fflags |= NOTE_ADAPTIVE_WTIMO;
	}
	if (ev_hint & SO_FILT_HINT_ADAPTIVE_RTIMO) {
		kn->kn_fflags |= NOTE_ADAPTIVE_RTIMO;
	}
	if ((ev_hint & SO_FILT_HINT_CONNECTED) ||
	    (so->so_state & SS_ISCONNECTED)) {
		kn->kn_fflags |= NOTE_CONNECTED;
		level_trigger |= NOTE_CONNECTED;
	}
	if ((ev_hint & SO_FILT_HINT_DISCONNECTED) ||
	    (so->so_state & SS_ISDISCONNECTED)) {
		kn->kn_fflags |= NOTE_DISCONNECTED;
		level_trigger |= NOTE_DISCONNECTED;
	}
	if (ev_hint & SO_FILT_HINT_CONNINFO_UPDATED) {
		if (so->so_proto != NULL &&
		    (so->so_proto->pr_flags & PR_EVCONNINFO))
			kn->kn_fflags |= NOTE_CONNINFO_UPDATED;
	}

	if ((so->so_state & SS_CANTRCVMORE)
#if CONTENT_FILTER
	    && cfil_sock_data_pending(&so->so_rcv) == 0
#endif /* CONTENT_FILTER */
	    ) {
		kn->kn_fflags |= NOTE_READCLOSED;
		level_trigger |= NOTE_READCLOSED;
	}

	if (so->so_state & SS_CANTSENDMORE) {
		kn->kn_fflags |= NOTE_WRITECLOSED;
		level_trigger |= NOTE_WRITECLOSED;
	}

	if ((ev_hint & SO_FILT_HINT_SUSPEND) ||
	    (so->so_flags & SOF_SUSPENDED)) {
		kn->kn_fflags &= ~(NOTE_SUSPEND | NOTE_RESUME);

		/* If resume event was delivered before, reset it */
		kn->kn_hookid &= ~NOTE_RESUME;

		kn->kn_fflags |= NOTE_SUSPEND;
		level_trigger |= NOTE_SUSPEND;
	}

	if ((ev_hint & SO_FILT_HINT_RESUME) ||
	    (so->so_flags & SOF_SUSPENDED) == 0) {
		kn->kn_fflags &= ~(NOTE_SUSPEND | NOTE_RESUME);

		/* If suspend event was delivered before, reset it */
		kn->kn_hookid &= ~NOTE_SUSPEND;

		kn->kn_fflags |= NOTE_RESUME;
		level_trigger |= NOTE_RESUME;
	}

	if (so->so_error != 0) {
		ret = 1;
		kn->kn_data = so->so_error;
		kn->kn_flags |= EV_EOF;
	} else {
		get_sockev_state(so, (u_int32_t *)&(kn->kn_data));
	}

	/* Reset any events that are not requested on this knote */
	kn->kn_fflags &= (kn->kn_sfflags & EVFILT_SOCK_ALL_MASK);
	level_trigger &= (kn->kn_sfflags & EVFILT_SOCK_ALL_MASK);

	/* Find the level triggerred events that are already delivered */
	level_trigger &= kn->kn_hookid;
	level_trigger &= EVFILT_SOCK_LEVEL_TRIGGER_MASK;

	/* Do not deliver level triggerred events more than once */
	if ((kn->kn_fflags & ~level_trigger) != 0)
		ret = 1;

	if (locked)
		socket_unlock(so, 1);

	return (ret);
}

static void
filt_socktouch(struct knote *kn, struct kevent_internal_s *kev, long type)
{
#pragma unused(kev)
	switch (type) {
	case EVENT_REGISTER:
	{
		uint32_t changed_flags;
		changed_flags = (kn->kn_sfflags ^ kn->kn_hookid);

		/*
		 * Since we keep track of events that are already
		 * delivered, if any of those events are not requested
		 * anymore the state related to them can be reset
		 */
		kn->kn_hookid &=
		    ~(changed_flags & EVFILT_SOCK_LEVEL_TRIGGER_MASK);
		break;
	}
	case EVENT_PROCESS:
		/*
		 * Store the state of the events being delivered. This
		 * state can be used to deliver level triggered events
		 * ateast once and still avoid waking up the application
		 * multiple times as long as the event is active.
		 */
		if (kn->kn_fflags != 0)
			kn->kn_hookid |= (kn->kn_fflags &
				EVFILT_SOCK_LEVEL_TRIGGER_MASK);

		/*
		 * NOTE_RESUME and NOTE_SUSPEND are an exception, deliver
		 * only one of them and remember the last one that was
		 * delivered last
		 */
		if (kn->kn_fflags & NOTE_SUSPEND)
			kn->kn_hookid &= ~NOTE_RESUME;
		if (kn->kn_fflags & NOTE_RESUME)
			kn->kn_hookid &= ~NOTE_SUSPEND;
		break;
	default:
		break;
	}
}

void
get_sockev_state(struct socket *so, u_int32_t *statep)
{
	u_int32_t state = *(statep);

	if (so->so_state & SS_ISCONNECTED)
		state |= SOCKEV_CONNECTED;
	else
		state &= ~(SOCKEV_CONNECTED);
	state |= ((so->so_state & SS_ISDISCONNECTED) ? SOCKEV_DISCONNECTED : 0);
	*(statep) = state;
}

#define	SO_LOCK_HISTORY_STR_LEN \
	(2 * SO_LCKDBG_MAX * (2 + (2 * sizeof (void *)) + 1) + 1)

__private_extern__ const char *
solockhistory_nr(struct socket *so)
{
	size_t n = 0;
	int i;
	static char lock_history_str[SO_LOCK_HISTORY_STR_LEN];

	bzero(lock_history_str, sizeof (lock_history_str));
	for (i = SO_LCKDBG_MAX - 1; i >= 0; i--) {
		n += snprintf(lock_history_str + n,
		    SO_LOCK_HISTORY_STR_LEN - n, "%p:%p ",
		    so->lock_lr[(so->next_lock_lr + i) % SO_LCKDBG_MAX],
		    so->unlock_lr[(so->next_unlock_lr + i) % SO_LCKDBG_MAX]);
	}
	return (lock_history_str);
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

	if (so->so_proto == NULL) {
		panic("%s: null so_proto so=%p\n", __func__, so);
		/* NOTREACHED */
	}

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
			if (so->so_usecount <= 0) {
				panic("%s: bad refcount=%d so=%p (%d, %d, %d) "
				    "lrh=%s", __func__, so->so_usecount, so,
				    SOCK_DOM(so), so->so_type,
				    SOCK_PROTO(so), solockhistory_nr(so));
				/* NOTREACHED */
			}

			so->so_usecount--;
			if (so->so_usecount == 0)
				sofreelastref(so, 1);
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

void
soif2kcl(struct socket *so, boolean_t set)
{
	if (set)
		so->so_flags1 |= SOF1_IF_2KCL;
	else
		so->so_flags1 &= ~SOF1_IF_2KCL;
}

int
so_isdstlocal(struct socket *so) {

	struct inpcb *inp = (struct inpcb *)so->so_pcb;

	if (SOCK_DOM(so) == PF_INET)
		return (inaddr_local(inp->inp_faddr));
	else if (SOCK_DOM(so) == PF_INET6)
		return (in6addr_local(&inp->in6p_faddr));

	return (0);
}

int
sosetdefunct(struct proc *p, struct socket *so, int level, boolean_t noforce)
{
	struct sockbuf *rcv, *snd;
	int err = 0, defunct;

	rcv = &so->so_rcv;
	snd = &so->so_snd;

	defunct = (so->so_flags & SOF_DEFUNCT);
	if (defunct) {
		if (!(snd->sb_flags & rcv->sb_flags & SB_DROP)) {
			panic("%s: SB_DROP not set", __func__);
			/* NOTREACHED */
		}
		goto done;
	}

	if (so->so_flags & SOF_NODEFUNCT) {
		if (noforce) {
			err = EOPNOTSUPP;
			SODEFUNCTLOG(("%s[%d]: (target pid %d level %d) "
			    "so 0x%llx [%d,%d] is not eligible for defunct "
			    "(%d)\n", __func__, proc_selfpid(), proc_pid(p),
			    level, (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
			    SOCK_DOM(so), SOCK_TYPE(so), err));
			return (err);
		}
		so->so_flags &= ~SOF_NODEFUNCT;
		SODEFUNCTLOG(("%s[%d]: (target pid %d level %d) so 0x%llx "
		    "[%d,%d] defunct by force\n", __func__, proc_selfpid(),
		    proc_pid(p), level, (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
		    SOCK_DOM(so), SOCK_TYPE(so)));
	} else if (so->so_flags1 & SOF1_EXTEND_BK_IDLE_WANTED) {
		struct inpcb *inp = (struct inpcb *)so->so_pcb;
		struct ifnet *ifp = inp->inp_last_outifp;

		if (ifp && IFNET_IS_CELLULAR(ifp)) {
			OSIncrementAtomic(&soextbkidlestat.so_xbkidle_nocell);
		} else if (so->so_flags & SOF_DELEGATED) {
			OSIncrementAtomic(&soextbkidlestat.so_xbkidle_nodlgtd);
		} else if (soextbkidlestat.so_xbkidle_time == 0) {
			OSIncrementAtomic(&soextbkidlestat.so_xbkidle_notime);
		} else if (noforce) {
			OSIncrementAtomic(&soextbkidlestat.so_xbkidle_active);
		
			so->so_flags1 |= SOF1_EXTEND_BK_IDLE_INPROG;
			so->so_extended_bk_start = net_uptime();
			OSBitOrAtomic(P_LXBKIDLEINPROG, &p->p_ladvflag);
			
			inpcb_timer_sched(inp->inp_pcbinfo, INPCB_TIMER_LAZY);
			
			err = EOPNOTSUPP;
			SODEFUNCTLOG(("%s[%d]: (target pid %d level %d) "
			    "extend bk idle "
			    "so 0x%llx rcv hw %d cc %d\n",
			    __func__, proc_selfpid(), proc_pid(p),
			    level, (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
			    so->so_rcv.sb_hiwat, so->so_rcv.sb_cc));
			return (err);
		} else {
			OSIncrementAtomic(&soextbkidlestat.so_xbkidle_forced);
		}
	}

	so->so_flags |= SOF_DEFUNCT;

	/* Prevent further data from being appended to the socket buffers */
	snd->sb_flags |= SB_DROP;
	rcv->sb_flags |= SB_DROP;

	/* Flush any existing data in the socket buffers */
	if (rcv->sb_cc != 0) {
		rcv->sb_flags &= ~SB_SEL;
		selthreadclear(&rcv->sb_sel);
		sbrelease(rcv);
	}
	if (snd->sb_cc != 0) {
		snd->sb_flags &= ~SB_SEL;
		selthreadclear(&snd->sb_sel);
		sbrelease(snd);
	}

done:
	SODEFUNCTLOG(("%s[%d]: (target pid %d level %d) so 0x%llx [%d,%d] %s "
	    "defunct%s\n", __func__, proc_selfpid(), proc_pid(p), level,
	    (uint64_t)DEBUG_KERNEL_ADDRPERM(so), SOCK_DOM(so), SOCK_TYPE(so),
	    defunct ? "is already" : "marked as",
	    (so->so_flags1 & SOF1_EXTEND_BK_IDLE_WANTED) ? " extbkidle" : ""));

	return (err);
}

int
sodefunct(struct proc *p, struct socket *so, int level)
{
	struct sockbuf *rcv, *snd;

	if (!(so->so_flags & SOF_DEFUNCT)) {
		panic("%s improperly called", __func__);
		/* NOTREACHED */
	}
	if (so->so_state & SS_DEFUNCT)
		goto done;

	rcv = &so->so_rcv;
	snd = &so->so_snd;

	if (SOCK_DOM(so) == PF_INET || SOCK_DOM(so) == PF_INET6) {
		char s[MAX_IPv6_STR_LEN];
		char d[MAX_IPv6_STR_LEN];
		struct inpcb *inp = sotoinpcb(so);

		SODEFUNCTLOG(("%s[%d]: (target pid %d level %d) so 0x%llx [%s "
		    "%s:%d -> %s:%d] is now defunct [rcv_si 0x%x, snd_si 0x%x, "
		    "rcv_fl 0x%x, snd_fl 0x%x]\n", __func__, proc_selfpid(),
		    proc_pid(p), level, (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
		    (SOCK_TYPE(so) == SOCK_STREAM) ? "TCP" : "UDP",
		    inet_ntop(SOCK_DOM(so), ((SOCK_DOM(so) == PF_INET) ?
		    (void *)&inp->inp_laddr.s_addr : (void *)&inp->in6p_laddr),
		    s, sizeof (s)), ntohs(inp->in6p_lport),
		    inet_ntop(SOCK_DOM(so), (SOCK_DOM(so) == PF_INET) ?
		    (void *)&inp->inp_faddr.s_addr : (void *)&inp->in6p_faddr,
		    d, sizeof (d)), ntohs(inp->in6p_fport),
		    (uint32_t)rcv->sb_sel.si_flags,
		    (uint32_t)snd->sb_sel.si_flags,
		    rcv->sb_flags, snd->sb_flags));
	} else {
		SODEFUNCTLOG(("%s[%d]: (target pid %d level %d) so 0x%llx "
		    "[%d,%d] is now defunct [rcv_si 0x%x, snd_si 0x%x, "
		    "rcv_fl 0x%x, snd_fl 0x%x]\n", __func__, proc_selfpid(),
		    proc_pid(p), level, (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
		    SOCK_DOM(so), SOCK_TYPE(so), (uint32_t)rcv->sb_sel.si_flags,
		    (uint32_t)snd->sb_sel.si_flags, rcv->sb_flags,
		    snd->sb_flags));
	}

	/*
	 * Unwedge threads blocked on sbwait() and sb_lock().
	 */
	sbwakeup(rcv);
	sbwakeup(snd);

	so->so_flags1 |= SOF1_DEFUNCTINPROG;
	if (rcv->sb_flags & SB_LOCK)
		sbunlock(rcv, TRUE);	/* keep socket locked */
	if (snd->sb_flags & SB_LOCK)
		sbunlock(snd, TRUE);	/* keep socket locked */

	/*
	 * Flush the buffers and disconnect.  We explicitly call shutdown
	 * on both data directions to ensure that SS_CANT{RCV,SEND}MORE
	 * states are set for the socket.  This would also flush out data
	 * hanging off the receive list of this socket.
	 */
	(void) soshutdownlock_final(so, SHUT_RD);
	(void) soshutdownlock_final(so, SHUT_WR);
	(void) sodisconnectlocked(so);

	/*
	 * Explicitly handle connectionless-protocol disconnection
	 * and release any remaining data in the socket buffers.
	 */
	if (!(so->so_flags & SS_ISDISCONNECTED))
		(void) soisdisconnected(so);

	if (so->so_error == 0)
		so->so_error = EBADF;

	if (rcv->sb_cc != 0) {
		rcv->sb_flags &= ~SB_SEL;
		selthreadclear(&rcv->sb_sel);
		sbrelease(rcv);
	}
	if (snd->sb_cc != 0) {
		snd->sb_flags &= ~SB_SEL;
		selthreadclear(&snd->sb_sel);
		sbrelease(snd);
	}
	so->so_state |= SS_DEFUNCT;

done:
	return (0);
}

int
soresume(struct proc *p, struct socket *so, int locked)
{
	if (locked == 0)
		socket_lock(so, 1);

	if (so->so_flags1 & SOF1_EXTEND_BK_IDLE_INPROG) {
		SODEFUNCTLOG(("%s[%d]: )target pid %d) so 0x%llx [%d,%d] "
		    "resumed from bk idle\n",
		    __func__, proc_selfpid(), proc_pid(p),
		    (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
		    SOCK_DOM(so), SOCK_TYPE(so)));

		so->so_flags1 &= ~SOF1_EXTEND_BK_IDLE_INPROG;
		so->so_extended_bk_start = 0;
		OSBitAndAtomic(~P_LXBKIDLEINPROG, &p->p_ladvflag);

		OSIncrementAtomic(&soextbkidlestat.so_xbkidle_resumed);
		OSDecrementAtomic(&soextbkidlestat.so_xbkidle_active);
		VERIFY(soextbkidlestat.so_xbkidle_active >= 0);
	}
	if (locked == 0)
		socket_unlock(so, 1);

	return (0);
}

/*
 * Does not attempt to account for sockets that are delegated from
 * the current process
 */
int
so_set_extended_bk_idle(struct socket *so, int optval)
{
	int error = 0;

	if ((SOCK_DOM(so) != PF_INET && SOCK_DOM(so) != PF_INET6) ||
	    SOCK_PROTO(so) != IPPROTO_TCP) {
		OSDecrementAtomic(&soextbkidlestat.so_xbkidle_notsupp);
		error = EOPNOTSUPP;
	} else if (optval == 0) {
		so->so_flags1 &= ~SOF1_EXTEND_BK_IDLE_WANTED;

		soresume(current_proc(), so, 1);
	} else {
		struct proc *p = current_proc();
		int i;
		struct filedesc *fdp;
		int count = 0;

		proc_fdlock(p);

		fdp = p->p_fd;
		for (i = 0; i < fdp->fd_nfiles; i++) {
			struct fileproc *fp = fdp->fd_ofiles[i];
			struct socket *so2;

			if (fp == NULL ||
			    (fdp->fd_ofileflags[i] & UF_RESERVED) != 0 ||
			    FILEGLOB_DTYPE(fp->f_fglob) != DTYPE_SOCKET)
				continue;

			so2 = (struct socket *)fp->f_fglob->fg_data;
			if (so != so2 &&
			    so2->so_flags1 & SOF1_EXTEND_BK_IDLE_WANTED)
				count++;
			if (count >= soextbkidlestat.so_xbkidle_maxperproc)
				break;
		}
		if (count >= soextbkidlestat.so_xbkidle_maxperproc) {
			OSIncrementAtomic(&soextbkidlestat.so_xbkidle_toomany);
			error = EBUSY;
		} else if (so->so_flags & SOF_DELEGATED) {
			OSIncrementAtomic(&soextbkidlestat.so_xbkidle_nodlgtd);
			error = EBUSY;
		} else {
			so->so_flags1 |= SOF1_EXTEND_BK_IDLE_WANTED;
			OSIncrementAtomic(&soextbkidlestat.so_xbkidle_wantok);
		}
		SODEFUNCTLOG(("%s[%d]: so 0x%llx [%d,%d] "
		    "%s marked for extended bk idle\n",
		    __func__, proc_selfpid(),
		    (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
		    SOCK_DOM(so), SOCK_TYPE(so),
		    (so->so_flags1 & SOF1_EXTEND_BK_IDLE_WANTED) ?
		    "is" : "not"));

		proc_fdunlock(p);
	}

	return (error);
}

static void
so_stop_extended_bk_idle(struct socket *so)
{
	so->so_flags1 &= ~SOF1_EXTEND_BK_IDLE_INPROG;
	so->so_extended_bk_start = 0;

	OSDecrementAtomic(&soextbkidlestat.so_xbkidle_active);
	VERIFY(soextbkidlestat.so_xbkidle_active >= 0);
	/*
	 * Force defunct
	 */
	sosetdefunct(current_proc(), so,
	    SHUTDOWN_SOCKET_LEVEL_DISCONNECT_INTERNAL, FALSE);
	if (so->so_flags & SOF_DEFUNCT) {
		sodefunct(current_proc(), so,
		    SHUTDOWN_SOCKET_LEVEL_DISCONNECT_INTERNAL);
	}
}

void
so_drain_extended_bk_idle(struct socket *so)
{
	if (so && (so->so_flags1 & SOF1_EXTEND_BK_IDLE_INPROG)) {
		/*
		 * Only penalize sockets that have outstanding data
		 */
		if (so->so_rcv.sb_cc || so->so_snd.sb_cc) {
			so_stop_extended_bk_idle(so);

			OSIncrementAtomic(&soextbkidlestat.so_xbkidle_drained);
		}
	}
}

/*
 * Return values tells if socket is still in extended background idle
 */
int
so_check_extended_bk_idle_time(struct socket *so)
{
	int ret = 1;

	if ((so->so_flags1 & SOF1_EXTEND_BK_IDLE_INPROG)) {
		SODEFUNCTLOG(("%s[%d]: so 0x%llx [%d,%d]\n",
		    __func__, proc_selfpid(),
		    (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
		    SOCK_DOM(so), SOCK_TYPE(so)));
		if (net_uptime() - so->so_extended_bk_start >
		    soextbkidlestat.so_xbkidle_time) {
			so_stop_extended_bk_idle(so);

			OSIncrementAtomic(&soextbkidlestat.so_xbkidle_expired);

			ret = 0;
		} else {
			struct inpcb *inp = (struct inpcb *)so->so_pcb;

			inpcb_timer_sched(inp->inp_pcbinfo, INPCB_TIMER_LAZY);
			OSIncrementAtomic(&soextbkidlestat.so_xbkidle_resched);
		}
	}
	
	return (ret);
}

void
resume_proc_sockets(proc_t p)
{
	if (p->p_ladvflag & P_LXBKIDLEINPROG) {
		struct filedesc	*fdp;
		int i;

		proc_fdlock(p);
		fdp = p->p_fd;
		for (i = 0; i < fdp->fd_nfiles; i++) {
			struct fileproc	*fp;
			struct socket *so;

			fp = fdp->fd_ofiles[i];
			if (fp == NULL || 
			    (fdp->fd_ofileflags[i] & UF_RESERVED) != 0 ||
			    FILEGLOB_DTYPE(fp->f_fglob) != DTYPE_SOCKET)
				continue;

			so = (struct socket *)fp->f_fglob->fg_data;
			(void) soresume(p, so, 0);
		}
		proc_fdunlock(p);

		OSBitAndAtomic(~P_LXBKIDLEINPROG, &p->p_ladvflag);
	}
}

__private_extern__ int
so_set_recv_anyif(struct socket *so, int optval)
{
	int ret = 0;

#if INET6
	if (SOCK_DOM(so) == PF_INET || SOCK_DOM(so) == PF_INET6) {
#else
	if (SOCK_DOM(so) == PF_INET) {
#endif /* !INET6 */
		if (optval)
			sotoinpcb(so)->inp_flags |= INP_RECV_ANYIF;
		else
			sotoinpcb(so)->inp_flags &= ~INP_RECV_ANYIF;
	}

	return (ret);
}

__private_extern__ int
so_get_recv_anyif(struct socket *so)
{
	int ret = 0;

#if INET6
	if (SOCK_DOM(so) == PF_INET || SOCK_DOM(so) == PF_INET6) {
#else
	if (SOCK_DOM(so) == PF_INET) {
#endif /* !INET6 */
		ret = (sotoinpcb(so)->inp_flags & INP_RECV_ANYIF) ? 1 : 0;
	}

	return (ret);
}

int
so_set_restrictions(struct socket *so, uint32_t vals)
{
	int nocell_old, nocell_new;
	int noexpensive_old, noexpensive_new;

	/*
	 * Deny-type restrictions are trapdoors; once set they cannot be
	 * unset for the lifetime of the socket.  This allows them to be
	 * issued by a framework on behalf of the application without
	 * having to worry that they can be undone.
	 *
	 * Note here that socket-level restrictions overrides any protocol
	 * level restrictions.  For instance, SO_RESTRICT_DENY_CELLULAR
	 * socket restriction issued on the socket has a higher precendence
	 * than INP_NO_IFT_CELLULAR.  The latter is affected by the UUID
	 * policy PROC_UUID_NO_CELLULAR for unrestricted sockets only,
	 * i.e. when SO_RESTRICT_DENY_CELLULAR has not been issued.
	 */
	nocell_old = (so->so_restrictions & SO_RESTRICT_DENY_CELLULAR);
	noexpensive_old = (so->so_restrictions & SO_RESTRICT_DENY_EXPENSIVE);
	so->so_restrictions |= (vals & (SO_RESTRICT_DENY_IN |
	    SO_RESTRICT_DENY_OUT | SO_RESTRICT_DENY_CELLULAR |
	    SO_RESTRICT_DENY_EXPENSIVE));
	nocell_new = (so->so_restrictions & SO_RESTRICT_DENY_CELLULAR);
	noexpensive_new = (so->so_restrictions & SO_RESTRICT_DENY_EXPENSIVE);

	/* we can only set, not clear restrictions */
	if ((nocell_new - nocell_old) == 0 &&
	    (noexpensive_new - noexpensive_old) == 0)
		return (0);
#if INET6
	if (SOCK_DOM(so) == PF_INET || SOCK_DOM(so) == PF_INET6) {
#else
	if (SOCK_DOM(so) == PF_INET) {
#endif /* !INET6 */
		if (nocell_new - nocell_old != 0) {
			/*
			 * if deny cellular is now set, do what's needed
			 * for INPCB
			 */
			inp_set_nocellular(sotoinpcb(so));
		}
		if (noexpensive_new - noexpensive_old != 0) {
			inp_set_noexpensive(sotoinpcb(so));
		}
	}

	return (0);
}

uint32_t
so_get_restrictions(struct socket *so)
{
	return (so->so_restrictions & (SO_RESTRICT_DENY_IN |
	    SO_RESTRICT_DENY_OUT |
	    SO_RESTRICT_DENY_CELLULAR | SO_RESTRICT_DENY_EXPENSIVE));
}

struct sockaddr_entry *
sockaddrentry_alloc(int how)
{
	struct sockaddr_entry *se;

	se = (how == M_WAITOK) ? zalloc(se_zone) : zalloc_noblock(se_zone);
	if (se != NULL)
		bzero(se, se_zone_size);

	return (se);
}

void
sockaddrentry_free(struct sockaddr_entry *se)
{
	if (se->se_addr != NULL) {
		FREE(se->se_addr, M_SONAME);
		se->se_addr = NULL;
	}
	zfree(se_zone, se);
}

struct sockaddr_entry *
sockaddrentry_dup(const struct sockaddr_entry *src_se, int how)
{
	struct sockaddr_entry *dst_se;

	dst_se = sockaddrentry_alloc(how);
	if (dst_se != NULL) {
		int len = src_se->se_addr->sa_len;

		MALLOC(dst_se->se_addr, struct sockaddr *,
		    len, M_SONAME, how | M_ZERO);
		if (dst_se->se_addr != NULL) {
			bcopy(src_se->se_addr, dst_se->se_addr, len);
		} else {
			sockaddrentry_free(dst_se);
			dst_se = NULL;
		}
	}

	return (dst_se);
}

struct sockaddr_list *
sockaddrlist_alloc(int how)
{
	struct sockaddr_list *sl;

	sl = (how == M_WAITOK) ? zalloc(sl_zone) : zalloc_noblock(sl_zone);
	if (sl != NULL) {
		bzero(sl, sl_zone_size);
		TAILQ_INIT(&sl->sl_head);
	}
	return (sl);
}

void
sockaddrlist_free(struct sockaddr_list *sl)
{
	struct sockaddr_entry *se, *tse;

	TAILQ_FOREACH_SAFE(se, &sl->sl_head, se_link, tse) {
		sockaddrlist_remove(sl, se);
		sockaddrentry_free(se);
	}
	VERIFY(sl->sl_cnt == 0 && TAILQ_EMPTY(&sl->sl_head));
	zfree(sl_zone, sl);
}

void
sockaddrlist_insert(struct sockaddr_list *sl, struct sockaddr_entry *se)
{
	VERIFY(!(se->se_flags & SEF_ATTACHED));
	se->se_flags |= SEF_ATTACHED;
	TAILQ_INSERT_TAIL(&sl->sl_head, se, se_link);
	sl->sl_cnt++;
	VERIFY(sl->sl_cnt != 0);
}

void
sockaddrlist_remove(struct sockaddr_list *sl, struct sockaddr_entry *se)
{
	VERIFY(se->se_flags & SEF_ATTACHED);
	se->se_flags &= ~SEF_ATTACHED;
	VERIFY(sl->sl_cnt != 0);
	sl->sl_cnt--;
	TAILQ_REMOVE(&sl->sl_head, se, se_link);
}

struct sockaddr_list *
sockaddrlist_dup(const struct sockaddr_list *src_sl, int how)
{
	struct sockaddr_entry *src_se, *tse;
	struct sockaddr_list *dst_sl;

	dst_sl = sockaddrlist_alloc(how);
	if (dst_sl == NULL)
		return (NULL);

	TAILQ_FOREACH_SAFE(src_se, &src_sl->sl_head, se_link, tse) {
		struct sockaddr_entry *dst_se;

		if (src_se->se_addr == NULL)
			continue;

		dst_se = sockaddrentry_dup(src_se, how);
		if (dst_se == NULL) {
			sockaddrlist_free(dst_sl);
			return (NULL);
		}

		sockaddrlist_insert(dst_sl, dst_se);
	}
	VERIFY(src_sl->sl_cnt == dst_sl->sl_cnt);

	return (dst_sl);
}

int
so_set_effective_pid(struct socket *so, int epid, struct proc *p)
{
	struct proc *ep = PROC_NULL;
	int error = 0;

	/* pid 0 is reserved for kernel */
	if (epid == 0) {
		error = EINVAL;
		goto done;
	}

	/*
	 * If this is an in-kernel socket, prevent its delegate
	 * association from changing unless the socket option is
	 * coming from within the kernel itself.
	 */
	if (so->last_pid == 0 && p != kernproc) {
		error = EACCES;
		goto done;
	}

	/*
	 * If this is issued by a process that's recorded as the
	 * real owner of the socket, or if the pid is the same as
	 * the process's own pid, then proceed.  Otherwise ensure
	 * that the issuing process has the necessary privileges.
	 */
	if (epid != so->last_pid || epid != proc_pid(p)) {
		if ((error = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_PRIVILEGED_SOCKET_DELEGATE, 0))) {
			error = EACCES;
			goto done;
		}
	}

	/* Find the process that corresponds to the effective pid */
	if ((ep = proc_find(epid)) == PROC_NULL) {
		error = ESRCH;
		goto done;
	}

	/*
	 * If a process tries to delegate the socket to itself, then
	 * there's really nothing to do; treat it as a way for the
	 * delegate association to be cleared.  Note that we check
	 * the passed-in proc rather than calling proc_selfpid(),
	 * as we need to check the process issuing the socket option
	 * which could be kernproc.  Given that we don't allow 0 for
	 * effective pid, it means that a delegated in-kernel socket
	 * stays delegated during its lifetime (which is probably OK.)
	 */
	if (epid == proc_pid(p)) {
		so->so_flags &= ~SOF_DELEGATED;
		so->e_upid = 0;
		so->e_pid = 0;
		uuid_clear(so->e_uuid);
	} else {
		so->so_flags |= SOF_DELEGATED;
		so->e_upid = proc_uniqueid(ep);
		so->e_pid = proc_pid(ep);
		proc_getexecutableuuid(ep, so->e_uuid, sizeof (so->e_uuid));
	}
done:
	if (error == 0 && net_io_policy_log) {
		uuid_string_t buf;

		uuid_unparse(so->e_uuid, buf);
		log(LOG_DEBUG, "%s[%s,%d]: so 0x%llx [%d,%d] epid %d (%s) "
		    "euuid %s%s\n", __func__, proc_name_address(p),
		    proc_pid(p), (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
		    SOCK_DOM(so), SOCK_TYPE(so),
		    so->e_pid, proc_name_address(ep), buf,
		    ((so->so_flags & SOF_DELEGATED) ? " [delegated]" : ""));
	} else if (error != 0 && net_io_policy_log) {
		log(LOG_ERR, "%s[%s,%d]: so 0x%llx [%d,%d] epid %d (%s) "
		    "ERROR (%d)\n", __func__, proc_name_address(p),
		    proc_pid(p), (uint64_t)DEBUG_KERNEL_ADDRPERM(so),
		    SOCK_DOM(so), SOCK_TYPE(so),
		    epid, (ep == PROC_NULL) ? "PROC_NULL" :
		    proc_name_address(ep), error);
	}

	/* Update this socket's policy upon success */
	if (error == 0) {
		so->so_policy_gencnt *= -1;
		so_update_policy(so);
#if NECP
		so_update_necp_policy(so, NULL, NULL);
#endif /* NECP */
	}

	if (ep != PROC_NULL)
		proc_rele(ep);

	return (error);
}

int
so_set_effective_uuid(struct socket *so, uuid_t euuid, struct proc *p)
{
	uuid_string_t buf;
	uuid_t uuid;
	int error = 0;

	/* UUID must not be all-zeroes (reserved for kernel) */
	if (uuid_is_null(euuid)) {
		error = EINVAL;
		goto done;
	}

	/*
	 * If this is an in-kernel socket, prevent its delegate
	 * association from changing unless the socket option is
	 * coming from within the kernel itself.
	 */
	if (so->last_pid == 0 && p != kernproc) {
		error = EACCES;
		goto done;
	}

	/* Get the UUID of the issuing process */
	proc_getexecutableuuid(p, uuid, sizeof (uuid));

	/*
	 * If this is issued by a process that's recorded as the
	 * real owner of the socket, or if the uuid is the same as
	 * the process's own uuid, then proceed.  Otherwise ensure
	 * that the issuing process has the necessary privileges.
	 */
	if (uuid_compare(euuid, so->last_uuid) != 0 ||
	    uuid_compare(euuid, uuid) != 0) {
		if ((error = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_PRIVILEGED_SOCKET_DELEGATE, 0))) {
			error = EACCES;
			goto done;
		}
	}

	/*
	 * If a process tries to delegate the socket to itself, then
	 * there's really nothing to do; treat it as a way for the
	 * delegate association to be cleared.  Note that we check
	 * the uuid of the passed-in proc rather than that of the
	 * current process, as we need to check the process issuing
	 * the socket option which could be kernproc itself.  Given
	 * that we don't allow 0 for effective uuid, it means that
	 * a delegated in-kernel socket stays delegated during its
	 * lifetime (which is okay.)
	 */
	if (uuid_compare(euuid, uuid) == 0) {
		so->so_flags &= ~SOF_DELEGATED;
		so->e_upid = 0;
		so->e_pid = 0;
		uuid_clear(so->e_uuid);
	} else {
		so->so_flags |= SOF_DELEGATED;
		/*
		 * Unlike so_set_effective_pid(), we only have the UUID
		 * here and the process ID is not known.  Inherit the
		 * real {pid,upid} of the socket.
		 */
		so->e_upid = so->last_upid;
		so->e_pid = so->last_pid;
		uuid_copy(so->e_uuid, euuid);
	}

done:
	if (error == 0 && net_io_policy_log) {
		uuid_unparse(so->e_uuid, buf);
		log(LOG_DEBUG, "%s[%s,%d]: so 0x%llx [%d,%d] epid %d "
		    "euuid %s%s\n", __func__, proc_name_address(p), proc_pid(p),
		    (uint64_t)DEBUG_KERNEL_ADDRPERM(so), SOCK_DOM(so),
		    SOCK_TYPE(so), so->e_pid, buf,
		    ((so->so_flags & SOF_DELEGATED) ? " [delegated]" : ""));
	} else if (error != 0 && net_io_policy_log) {
		uuid_unparse(euuid, buf);
		log(LOG_DEBUG, "%s[%s,%d]: so 0x%llx [%d,%d] euuid %s "
		    "ERROR (%d)\n", __func__, proc_name_address(p), proc_pid(p),
		    (uint64_t)DEBUG_KERNEL_ADDRPERM(so), SOCK_DOM(so),
		    SOCK_TYPE(so), buf, error);
	}

	/* Update this socket's policy upon success */
	if (error == 0) {
		so->so_policy_gencnt *= -1;
		so_update_policy(so);
#if NECP
		so_update_necp_policy(so, NULL, NULL);
#endif /* NECP */
	}

	return (error);
}

void
netpolicy_post_msg(uint32_t ev_code, struct netpolicy_event_data *ev_data,
    uint32_t ev_datalen)
{
	struct kev_msg ev_msg;

	/*
	 * A netpolicy event always starts with a netpolicy_event_data
	 * structure, but the caller can provide for a longer event
	 * structure to post, depending on the event code.
	 */
	VERIFY(ev_data != NULL && ev_datalen >= sizeof (*ev_data));

	bzero(&ev_msg, sizeof (ev_msg));
	ev_msg.vendor_code	= KEV_VENDOR_APPLE;
	ev_msg.kev_class	= KEV_NETWORK_CLASS;
	ev_msg.kev_subclass	= KEV_NETPOLICY_SUBCLASS;
	ev_msg.event_code	= ev_code;

	ev_msg.dv[0].data_ptr	= ev_data;
	ev_msg.dv[0].data_length = ev_datalen;

	kev_post_msg(&ev_msg);
}

void
socket_post_kev_msg(uint32_t ev_code,
    struct kev_socket_event_data *ev_data,
    uint32_t ev_datalen)
{
	struct kev_msg ev_msg;

	bzero(&ev_msg, sizeof(ev_msg));
	ev_msg.vendor_code = KEV_VENDOR_APPLE;
	ev_msg.kev_class = KEV_NETWORK_CLASS;
	ev_msg.kev_subclass = KEV_SOCKET_SUBCLASS;
	ev_msg.event_code = ev_code;

	ev_msg.dv[0].data_ptr = ev_data;
	ev_msg.dv[0]. data_length = ev_datalen;

	kev_post_msg(&ev_msg);
}

void
socket_post_kev_msg_closed(struct socket *so)
{
	struct kev_socket_closed ev;
	struct sockaddr *socksa = NULL, *peersa = NULL;
	int err;
	bzero(&ev, sizeof(ev));
	err = (*so->so_proto->pr_usrreqs->pru_sockaddr)(so, &socksa);
	if (err == 0) {
		err = (*so->so_proto->pr_usrreqs->pru_peeraddr)(so,
		    &peersa);
		if (err == 0) {
			memcpy(&ev.ev_data.kev_sockname, socksa,
			    min(socksa->sa_len,
			    sizeof (ev.ev_data.kev_sockname)));
			memcpy(&ev.ev_data.kev_peername, peersa,
			    min(peersa->sa_len,
			    sizeof (ev.ev_data.kev_peername)));
			socket_post_kev_msg(KEV_SOCKET_CLOSED,
			    &ev.ev_data, sizeof (ev));
		}
	}
	if (socksa != NULL)
		FREE(socksa, M_SONAME);
	if (peersa != NULL)
		FREE(peersa, M_SONAME);
}
