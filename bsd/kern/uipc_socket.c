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
/* Copyright (c) 1998, 1999 Apple Computer, Inc. All Rights Reserved */
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
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
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <kern/zalloc.h>
#include <kern/locks.h>
#include <machine/limits.h>

int			so_cache_hw = 0;
int			so_cache_timeouts = 0;
int			so_cache_max_freed = 0;
int			cached_sock_count = 0;
struct socket		*socket_cache_head = 0;
struct socket		*socket_cache_tail = 0;
u_long			so_cache_time = 0;
int			so_cache_init_done = 0;
struct zone		*so_cache_zone;
extern int		get_inpcb_str_size();
extern int		get_tcp_str_size();

static lck_grp_t		*so_cache_mtx_grp;
static lck_attr_t		*so_cache_mtx_attr;
static lck_grp_attr_t	*so_cache_mtx_grp_attr;
lck_mtx_t				*so_cache_mtx;

#include <machine/limits.h>

static void     filt_sordetach(struct knote *kn);
static int      filt_soread(struct knote *kn, long hint);
static void     filt_sowdetach(struct knote *kn);
static int      filt_sowrite(struct knote *kn, long hint);
static int      filt_solisten(struct knote *kn, long hint);

static struct filterops solisten_filtops =
  { 1, NULL, filt_sordetach, filt_solisten };
static struct filterops soread_filtops =
  { 1, NULL, filt_sordetach, filt_soread };
static struct filterops sowrite_filtops =
  { 1, NULL, filt_sowdetach, filt_sowrite };

#define EVEN_MORE_LOCKING_DEBUG 0
int socket_debug = 0;
int socket_zone = M_SOCKET;
so_gen_t	so_gencnt;	/* generation count for sockets */

MALLOC_DEFINE(M_SONAME, "soname", "socket name");
MALLOC_DEFINE(M_PCB, "pcb", "protocol control block");

#define DBG_LAYER_IN_BEG	NETDBG_CODE(DBG_NETSOCK, 0)
#define DBG_LAYER_IN_END	NETDBG_CODE(DBG_NETSOCK, 2)
#define DBG_LAYER_OUT_BEG	NETDBG_CODE(DBG_NETSOCK, 1)
#define DBG_LAYER_OUT_END	NETDBG_CODE(DBG_NETSOCK, 3)
#define DBG_FNC_SOSEND		NETDBG_CODE(DBG_NETSOCK, (4 << 8) | 1)
#define DBG_FNC_SORECEIVE	NETDBG_CODE(DBG_NETSOCK, (8 << 8))
#define DBG_FNC_SOSHUTDOWN      NETDBG_CODE(DBG_NETSOCK, (9 << 8))

#define MAX_SOOPTGETM_SIZE	(128 * MCLBYTES)


SYSCTL_DECL(_kern_ipc);

static int somaxconn = SOMAXCONN;
SYSCTL_INT(_kern_ipc, KIPC_SOMAXCONN, somaxconn, CTLFLAG_RW, &somaxconn,
	   0, "");

/* Should we get a maximum also ??? */
static int sosendmaxchain = 65536;
static int sosendminchain = 16384;
static int sorecvmincopy  = 16384;
SYSCTL_INT(_kern_ipc, OID_AUTO, sosendminchain, CTLFLAG_RW, &sosendminchain,
           0, "");
SYSCTL_INT(_kern_ipc, OID_AUTO, sorecvmincopy, CTLFLAG_RW, &sorecvmincopy,
           0, "");

void  so_cache_timer();

/*
 * Socket operation routines.
 * These routines are called by the routines in
 * sys_socket.c or from a system process, and
 * implement the semantics of socket operations by
 * switching out to the protocol specific routines.
 */

#ifdef __APPLE__

vm_size_t	so_cache_zone_element_size;

static int sodelayed_copy(struct socket *so, struct uio *uio, struct mbuf **free_list, int *resid);


void socketinit()
{
    vm_size_t	str_size;

	if (so_cache_init_done) {
		printf("socketinit: already called...\n");
		return;
	}

	/*
	 * allocate lock group attribute and group for socket cache mutex
	 */
	so_cache_mtx_grp_attr = lck_grp_attr_alloc_init();
	lck_grp_attr_setdefault(so_cache_mtx_grp_attr);

	so_cache_mtx_grp = lck_grp_alloc_init("so_cache", so_cache_mtx_grp_attr);
		
	/*
	 * allocate the lock attribute for socket cache mutex
	 */
	so_cache_mtx_attr = lck_attr_alloc_init();
	lck_attr_setdefault(so_cache_mtx_attr);

    so_cache_init_done = 1;

    so_cache_mtx = lck_mtx_alloc_init(so_cache_mtx_grp, so_cache_mtx_attr);	/* cached sockets mutex */
	
    if (so_cache_mtx == NULL)
		return; /* we're hosed... */

    str_size = (vm_size_t)( sizeof(struct socket) + 4 +
			    get_inpcb_str_size()  + 4 +
			    get_tcp_str_size());
    so_cache_zone = zinit (str_size, 120000*str_size, 8192, "socache zone");
#if TEMPDEBUG
    printf("cached_sock_alloc -- so_cache_zone size is %x\n", str_size);
#endif
    timeout(so_cache_timer, NULL, (SO_CACHE_FLUSH_INTERVAL * hz));

    so_cache_zone_element_size = str_size;

    sflt_init();

}

void   cached_sock_alloc(so, waitok)
struct socket **so;
int           waitok;

{
    caddr_t	temp;
    register u_long  offset;


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
	    bzero((caddr_t)*so, sizeof(struct socket));
#if TEMPDEBUG
	    kprintf("cached_sock_alloc - retreiving cached sock %x - count == %d\n", *so,
		   cached_sock_count);
#endif
	    (*so)->so_saved_pcb = temp;
	    (*so)->cached_in_sock_layer = 1;

    }
    else {
#if TEMPDEBUG
	    kprintf("Allocating cached sock %x from memory\n", *so);
#endif

	    lck_mtx_unlock(so_cache_mtx);

	    if (waitok)
		 *so = (struct socket *) zalloc(so_cache_zone);
	    else
		 *so = (struct socket *) zalloc_noblock(so_cache_zone);

	    if (*so == 0)
		 return;

	    bzero((caddr_t)*so, sizeof(struct socket));

	    /*
	     * Define offsets for extra structures into our single block of
	     * memory. Align extra structures on longword boundaries.
	     */


	    offset = (u_long) *so;
	    offset += sizeof(struct socket);
	    if (offset & 0x3) {
		offset += 4;
		offset &= 0xfffffffc;
	    }
	    (*so)->so_saved_pcb = (caddr_t) offset;
	    offset += get_inpcb_str_size();
	    if (offset & 0x3) {
		offset += 4;
		offset &= 0xfffffffc;
	    }

	    ((struct inpcb *) (*so)->so_saved_pcb)->inp_saved_ppcb = (caddr_t) offset;
#if TEMPDEBUG
	    kprintf("Allocating cached socket - %x, pcb=%x tcpcb=%x\n", *so,
		    (*so)->so_saved_pcb,
		    ((struct inpcb *)(*so)->so_saved_pcb)->inp_saved_ppcb);
#endif
    }

    (*so)->cached_in_sock_layer = 1;
}


void cached_sock_free(so) 
struct socket *so;
{

	lck_mtx_lock(so_cache_mtx);

	if (++cached_sock_count > MAX_CACHED_SOCKETS) {
		--cached_sock_count;
		lck_mtx_unlock(so_cache_mtx);
#if TEMPDEBUG
		kprintf("Freeing overflowed cached socket %x\n", so);
#endif
		zfree(so_cache_zone, so);
	}
	else {
#if TEMPDEBUG
		kprintf("Freeing socket %x into cache\n", so);
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
	kprintf("Freed cached sock %x into cache - count is %d\n", so, cached_sock_count);
#endif


}


void so_cache_timer()
{
	register struct socket	*p;
	register int		n_freed = 0;


	lck_mtx_lock(so_cache_mtx);

	++so_cache_time;

	while ( (p = socket_cache_tail) )
	{
		if ((so_cache_time - p->cache_timestamp) < SO_CACHE_TIME_LIMIT)
		        break;

		so_cache_timeouts++;
		
		if ( (socket_cache_tail = p->cache_prev) )
		        p->cache_prev->cache_next = 0;
		if (--cached_sock_count == 0)
		        socket_cache_head = 0;


		zfree(so_cache_zone, p);
		
		if (++n_freed >= SO_CACHE_MAX_FREE_BATCH)
		{
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
soalloc(waitok, dom, type)
	int waitok;
	int dom;
	int type;
{
	struct socket *so;

	if ((dom == PF_INET) && (type == SOCK_STREAM)) 
	    cached_sock_alloc(&so, waitok);
	else
	{
	     MALLOC_ZONE(so, struct socket *, sizeof(*so), socket_zone, M_WAITOK);
	     if (so) 
		  bzero(so, sizeof *so);
	}
	/* XXX race condition for reentrant kernel */
//###LD Atomic add for so_gencnt
	if (so) {
	     so->so_gencnt = ++so_gencnt;
	     so->so_zone = socket_zone;
	}

	return so;
}

int
socreate(dom, aso, type, proto)
	int dom;
	struct socket **aso;
	register int type;
	int proto;
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

	if (prp == 0 || prp->pr_usrreqs->pru_attach == 0)
		return (EPROTONOSUPPORT);
#ifndef __APPLE__

	if (p->p_prison && jail_socket_unixiproute_only &&
	    prp->pr_domain->dom_family != PF_LOCAL &&
	    prp->pr_domain->dom_family != PF_INET &&
	    prp->pr_domain->dom_family != PF_ROUTE) {
		return (EPROTONOSUPPORT);
	}
	
#endif
	if (prp->pr_type != type)
		return (EPROTOTYPE);
	so = soalloc(p != 0, dom, type);
	if (so == 0)
		return (ENOBUFS);

	TAILQ_INIT(&so->so_incomp);
	TAILQ_INIT(&so->so_comp);
	so->so_type = type;

#ifdef __APPLE__
	if (p != 0) {
		so->so_uid = kauth_cred_getuid(kauth_cred_get());
		if (!suser(kauth_cred_get(),NULL))
			so->so_state = SS_PRIV;
	}
#else
	so->so_cred = kauth_cred_get_with_ref();
#endif
	so->so_proto = prp;
#ifdef __APPLE__
	so->so_rcv.sb_flags |= SB_RECV;	/* XXX */
	so->so_rcv.sb_so = so->so_snd.sb_so = so;
#endif
	
//### Attachement will create the per pcb lock if necessary and increase refcount
	so->so_usecount++;	/* for creation, make sure it's done before socket is inserted in lists */

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

	*aso = so;
	return (0);
}

int
sobind(so, nam)
	struct socket *so;
	struct sockaddr *nam;

{
	struct proc *p = current_proc();
	int error = 0;
	struct socket_filter_entry	*filter;
	int						 	filtered = 0;

	socket_lock(so, 1);

	/* Socket filter */
	error = 0;
	for (filter = so->so_filt; filter && (error == 0);
		 filter = filter->sfe_next_onsocket) {
		if (filter->sfe_filter->sf_filter.sf_bind) {
			if (filtered == 0) {
				filtered = 1;
				sflt_use(so);
				socket_unlock(so, 0);
			}
			error = filter->sfe_filter->sf_filter.sf_bind(
						filter->sfe_cookie, so, nam);
		}
	}
	if (filtered != 0) {
		socket_lock(so, 0);
		sflt_unuse(so);
	}
	/* End socket filter */
	
	if (error == 0)
		error = (*so->so_proto->pr_usrreqs->pru_bind)(so, nam, p);
	
	socket_unlock(so, 1);
	
	if (error == EJUSTRETURN)
		error = 0;
	
	return (error);
}

void
sodealloc(so)
	struct socket *so;
{
	so->so_gencnt = ++so_gencnt;

#ifndef __APPLE__
	if (so->so_rcv.sb_hiwat)
		(void)chgsbsize(so->so_cred->cr_uidinfo,
		    &so->so_rcv.sb_hiwat, 0, RLIM_INFINITY);
	if (so->so_snd.sb_hiwat)
		(void)chgsbsize(so->so_cred->cr_uidinfo,
		    &so->so_snd.sb_hiwat, 0, RLIM_INFINITY);
#ifdef INET
	if (so->so_accf != NULL) {
		if (so->so_accf->so_accept_filter != NULL && 
			so->so_accf->so_accept_filter->accf_destroy != NULL) {
			so->so_accf->so_accept_filter->accf_destroy(so);
		}
		if (so->so_accf->so_accept_filter_str != NULL)
			FREE(so->so_accf->so_accept_filter_str, M_ACCF);
		FREE(so->so_accf, M_ACCF);
	}
#endif /* INET */
	kauth_cred_rele(so->so_cred);
	zfreei(so->so_zone, so);
#else
	if (so->cached_in_sock_layer == 1) 
	     cached_sock_free(so);
	else {
	     if (so->cached_in_sock_layer == -1)
			panic("sodealloc: double dealloc: so=%x\n", so);
	     so->cached_in_sock_layer = -1;
	     FREE_ZONE(so, sizeof(*so), so->so_zone);
	}
#endif /* __APPLE__ */
}

int
solisten(so, backlog)
	register struct socket *so;
	int backlog;

{
	struct proc *p = current_proc();
	int error;

	socket_lock(so, 1);
	
	{
		struct socket_filter_entry	*filter;
		int						 	filtered = 0;
		error = 0;
		for (filter = so->so_filt; filter && (error == 0);
			 filter = filter->sfe_next_onsocket) {
			if (filter->sfe_filter->sf_filter.sf_listen) {
				if (filtered == 0) {
					filtered = 1;
					sflt_use(so);
					socket_unlock(so, 0);
				}
				error = filter->sfe_filter->sf_filter.sf_listen(
							filter->sfe_cookie, so);
			}
		}
		if (filtered != 0) {
			socket_lock(so, 0);
			sflt_unuse(so);
		}
	}

	if (error == 0) {
		error = (*so->so_proto->pr_usrreqs->pru_listen)(so, p);
	}
	
	if (error) {
		socket_unlock(so, 1);
		if (error == EJUSTRETURN)
			error = 0;
		return (error);
	}
	
	if (TAILQ_EMPTY(&so->so_comp))
		so->so_options |= SO_ACCEPTCONN;
	if (backlog < 0 || backlog > somaxconn)
		backlog = somaxconn;
	so->so_qlimit = backlog;

	socket_unlock(so, 1);
	return (0);
}

void
sofreelastref(so, dealloc)
	register struct socket *so;
	int dealloc;
{
	int error;
	struct socket *head = so->so_head;

	/*### Assume socket is locked */

	/* Remove any filters - may be called more than once */
	sflt_termsock(so);
	
	if ((!(so->so_flags & SOF_PCBCLEARING)) || ((so->so_state & SS_NOFDREF) == 0)) {
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

/*
 * Close a socket on last file table reference removal.
 * Initiate disconnect if connected.
 * Free socket when disconnect complete.
 */
int
soclose_locked(so)
	register struct socket *so;
{
	int error = 0;
	lck_mtx_t * mutex_held;
	struct timespec ts;

	if (so->so_usecount == 0) {
		panic("soclose: so=%x refcount=0\n", so);
	}

	sflt_notify(so, sock_evt_closing, NULL);
	
	if ((so->so_options & SO_ACCEPTCONN)) {
		struct socket *sp;
		
		/* We do not want new connection to be added to the connection queues */
		so->so_options &= ~SO_ACCEPTCONN;
		
		while ((sp = TAILQ_FIRST(&so->so_incomp)) != NULL) {
			/* A bit tricky here. We need to keep
			 * a lock if it's a protocol global lock
			 * but we want the head, not the socket locked
			 * in the case of per-socket lock...
			 */
			if (so->so_proto->pr_getlock != NULL) {
				socket_unlock(so, 0);
				socket_lock(sp, 1);
			}
			(void) soabort(sp);
			if (so->so_proto->pr_getlock != NULL) {
				socket_unlock(sp, 1);
				socket_lock(so, 0);
			}
		}

		while ((sp = TAILQ_FIRST(&so->so_comp)) != NULL) {
			/* Dequeue from so_comp since sofree() won't do it */
			TAILQ_REMOVE(&so->so_comp, sp, so_list);			
			so->so_qlen--;

			if (so->so_proto->pr_getlock != NULL) {
				socket_unlock(so, 0);
				socket_lock(sp, 1);
			}

			sp->so_state &= ~SS_COMP;
			sp->so_head = NULL;

			(void) soabort(sp);
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
				ts.tv_nsec = (so->so_linger % 100) * NSEC_PER_USEC * 1000 * 10;
				error = msleep((caddr_t)&so->so_timeo, mutex_held,
				    PSOCK | PCATCH, "soclos", &ts);
				if (error) {
					/* It's OK when the time fires, don't report an error */
					if (error == EWOULDBLOCK)
						error = 0;
					break;
				}
			}
		}
	}
drop:
	if (so->so_usecount == 0)
		panic("soclose: usecount is zero so=%x\n", so);
	if (so->so_pcb && !(so->so_flags & SOF_PCBCLEARING)) {
		int error2 = (*so->so_proto->pr_usrreqs->pru_detach)(so);
		if (error == 0)
			error = error2;
	}
	if (so->so_usecount <= 0)
		panic("soclose: usecount is zero so=%x\n", so);
discard:
	if (so->so_pcb && so->so_state & SS_NOFDREF)
		panic("soclose: NOFDREF");
	so->so_state |= SS_NOFDREF;
#ifdef __APPLE__
	so->so_proto->pr_domain->dom_refs--;
	evsofree(so);
#endif
	so->so_usecount--;
	sofree(so);
	return (error);
}

int
soclose(so)
	register struct socket *so;
{
	int error = 0;
	socket_lock(so, 1);
	if (so->so_retaincnt == 0)
		error = soclose_locked(so);
	else {	/* if the FD is going away, but socket is retained in kernel remove its reference */
		so->so_usecount--;
		if (so->so_usecount < 2)
			panic("soclose: retaincnt non null and so=%x usecount=%x\n", so->so_usecount);
	}
	socket_unlock(so, 1);
	return (error);
}


/*
 * Must be called at splnet...
 */
//#### Should already be locked
int
soabort(so)
	struct socket *so;
{
	int error;

#ifdef MORE_LOCKING_DEBUG
	lck_mtx_t * mutex_held;

	if (so->so_proto->pr_getlock != NULL) 
		mutex_held = (*so->so_proto->pr_getlock)(so, 0);
	else 
		mutex_held = so->so_proto->pr_domain->dom_mtx;
	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
#endif

	error = (*so->so_proto->pr_usrreqs->pru_abort)(so);
	if (error) {
		sofree(so);
		return error;
	}
	return (0);
}

int
soacceptlock(so, nam, dolock)
	register struct socket *so;
	struct sockaddr **nam;
	int dolock;
{
	int error;

	if (dolock) socket_lock(so, 1);

	if ((so->so_state & SS_NOFDREF) == 0)
		panic("soaccept: !NOFDREF");
	so->so_state &= ~SS_NOFDREF;
	error = (*so->so_proto->pr_usrreqs->pru_accept)(so, nam);
    
	if (dolock) socket_unlock(so, 1);
	return (error);
}
int
soaccept(so, nam)
	register struct socket *so;
	struct sockaddr **nam;
{
	return (soacceptlock(so, nam, 1));
}

int
soconnectlock(so, nam, dolock)
	register struct socket *so;
	struct sockaddr *nam;
	int dolock;

{
	int s;
	int error;
	struct proc *p = current_proc();

	if (dolock) socket_lock(so, 1);

	if (so->so_options & SO_ACCEPTCONN) {
		if (dolock) socket_unlock(so, 1);
		return (EOPNOTSUPP);
	}
	/*
	 * If protocol is connection-based, can only connect once.
	 * Otherwise, if connected, try to disconnect first.
	 * This allows user to disconnect by connecting to, e.g.,
	 * a null address.
	 */
	if (so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING) &&
	    ((so->so_proto->pr_flags & PR_CONNREQUIRED) ||
	    (error = sodisconnectlocked(so))))
		error = EISCONN;
	else {
		/*
		 * Run connect filter before calling protocol:
		 *  - non-blocking connect returns before completion;
		 */
		{
			struct socket_filter_entry	*filter;
			int						 	filtered = 0;
			error = 0;
			for (filter = so->so_filt; filter && (error == 0);
				 filter = filter->sfe_next_onsocket) {
				if (filter->sfe_filter->sf_filter.sf_connect_out) {
					if (filtered == 0) {
						filtered = 1;
						sflt_use(so);
						socket_unlock(so, 0);
					}
					error = filter->sfe_filter->sf_filter.sf_connect_out(
								filter->sfe_cookie, so, nam);
				}
			}
			if (filtered != 0) {
				socket_lock(so, 0);
				sflt_unuse(so);
			}
		}
		if (error) {
			if (error == EJUSTRETURN)
				error = 0;
			if (dolock) socket_unlock(so, 1);
			return error;
		}
		
		error = (*so->so_proto->pr_usrreqs->pru_connect)(so, nam, p);
	}
	if (dolock) socket_unlock(so, 1);
	return (error);
}

int
soconnect(so, nam)
	register struct socket *so;
	struct sockaddr *nam;
{
	return (soconnectlock(so, nam, 1));
}

int
soconnect2(so1, so2)
	register struct socket *so1;
	struct socket *so2;
{
	int error;
//####### Assumes so1 is already locked /

	socket_lock(so2, 1);

	error = (*so1->so_proto->pr_usrreqs->pru_connect2)(so1, so2);
	
	socket_unlock(so2, 1);
	return (error);
}


int
sodisconnectlocked(so)
	register struct socket *so;
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
//### Locking version
int
sodisconnect(so)
	register struct socket *so;
{
	int error; 

	socket_lock(so, 1);
	error = sodisconnectlocked(so);
	socket_unlock(so, 1);
	return(error);
}

#define	SBLOCKWAIT(f)	(((f) & MSG_DONTWAIT) ? M_DONTWAIT : M_WAIT)

/*
 * sosendcheck will lock the socket buffer if it isn't locked and
 * verify that there is space for the data being inserted.
 */

static int
sosendcheck(
	struct socket *so,
	struct sockaddr *addr,
	long resid,
	long clen,
	long atomic,
	int flags,
	int *sblocked)
{
	int error = 0;
	long space;
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
		}
		else {
			error = sblock(&so->so_snd, SBLOCKWAIT(flags));
			if (error) {
				return error;
			}
			*sblocked = 1;
		}
	}
	
	if (so->so_state & SS_CANTSENDMORE) 
		return EPIPE;
	
	if (so->so_error) {
		error = so->so_error;
		so->so_error = 0;
		return error;
	}
	
	if ((so->so_state & SS_ISCONNECTED) == 0) {
		/*
		 * `sendto' and `sendmsg' is allowed on a connection-
		 * based socket if it supports implied connect.
		 * Return ENOTCONN if not connected and no address is
		 * supplied.
		 */
		if ((so->so_proto->pr_flags & PR_CONNREQUIRED) &&
			(so->so_proto->pr_flags & PR_IMPLOPCL) == 0) {
			if ((so->so_state & SS_ISCONFIRMING) == 0 &&
				!(resid == 0 && clen != 0))
				return ENOTCONN;
		} else if (addr == 0 && !(flags&MSG_HOLD))
			return (so->so_proto->pr_flags & PR_CONNREQUIRED) ? ENOTCONN : EDESTADDRREQ;
	}
	space = sbspace(&so->so_snd);
	if (flags & MSG_OOB)
		space += 1024;
	if ((atomic && resid > so->so_snd.sb_hiwat) ||
		clen > so->so_snd.sb_hiwat)
		return EMSGSIZE;
	if (space < resid + clen && 
		(atomic || space < so->so_snd.sb_lowat || space < clen)) {
		if ((so->so_state & SS_NBIO) || (flags & MSG_NBIO) || assumelock) {
			return EWOULDBLOCK;
		}
		sbunlock(&so->so_snd, 1);
		error = sbwait(&so->so_snd);
		if (error) {
			return error;
		}
		goto restart;
	}
	
	return 0;
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
 */
int
sosend(so, addr, uio, top, control, flags)
	register struct socket *so;
	struct sockaddr *addr;
	struct uio *uio;
	struct mbuf *top;
	struct mbuf *control;
	int flags;

{
	struct mbuf **mp;
	register struct mbuf *m, *freelist = NULL;
	register long space, len, resid;
	int clen = 0, error, dontroute, mlen, sendflags;
	int atomic = sosendallatonce(so) || top;
	int sblocked = 0;
	struct proc *p = current_proc();

	if (uio)
		// LP64todo - fix this!
		resid = uio_resid(uio);
	else
		resid = top->m_pkthdr.len;

	KERNEL_DEBUG((DBG_FNC_SOSEND | DBG_FUNC_START),
		     so,
		     resid,
		     so->so_snd.sb_cc,
		     so->so_snd.sb_lowat,
		     so->so_snd.sb_hiwat);

	socket_lock(so, 1);

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
	if (p)
		p->p_stats->p_ru.ru_msgsnd++;
	if (control)
		clen = control->m_len;

	do {
		error = sosendcheck(so, addr, resid, clen, atomic, flags, &sblocked);
		if (error) {
			goto release;
		}
		mp = &top;
		space = sbspace(&so->so_snd) - clen + ((flags & MSG_OOB) ? 1024 : 0);

		do {
			
		    if (uio == NULL) {
				/*
				 * Data is prepackaged in "top".
				 */
				resid = 0;
				if (flags & MSG_EOR)
					top->m_flags |= M_EOR;
			} else {
				int             chainlength;
				int             bytes_to_copy;
	
				bytes_to_copy = min(resid, space);
	
				if (sosendminchain > 0) {
					chainlength = 0;
				} else
					chainlength = sosendmaxchain;
	
				socket_unlock(so, 0);
	
				do {
					int num_needed;
					int hdrs_needed = (top == 0) ? 1 : 0;
					
					/*
					 * try to maintain a local cache of mbuf clusters needed to complete this write
					 * the list is further limited to the number that are currently needed to fill the socket
					 * this mechanism allows a large number of mbufs/clusters to be grabbed under a single 
					 * mbuf lock... if we can't get any clusters, than fall back to trying for mbufs
					 * if we fail early (or miscalcluate the number needed) make sure to release any clusters
					 * we haven't yet consumed.
					 */
					if (freelist == NULL && bytes_to_copy > MCLBYTES) {
						num_needed = bytes_to_copy / NBPG;

						if ((bytes_to_copy - (num_needed * NBPG)) >= MINCLSIZE)
							num_needed++;
						
						freelist = m_getpackets_internal(&num_needed, hdrs_needed, M_WAIT, 0, NBPG);
						/* Fall back to cluster size if allocation failed */
					}
					
					if (freelist == NULL && bytes_to_copy > MINCLSIZE) {
						num_needed = bytes_to_copy / MCLBYTES;
					
						if ((bytes_to_copy - (num_needed * MCLBYTES)) >= MINCLSIZE)
							num_needed++;
						
						freelist = m_getpackets_internal(&num_needed, hdrs_needed, M_WAIT, 0, MCLBYTES);
						/* Fall back to a single mbuf if allocation failed */
					}
					
					if (freelist == NULL) {
						if (top == 0)
							MGETHDR(freelist, M_WAIT, MT_DATA);
						else
							MGET(freelist, M_WAIT, MT_DATA);

						if (freelist == NULL) {
							error = ENOBUFS;
							socket_lock(so, 0);
							goto release;
						}
						/*
						 * For datagram protocols, leave room
						 * for protocol headers in first mbuf.
						 */
						if (atomic && top == 0 && bytes_to_copy < MHLEN)
							MH_ALIGN(freelist, bytes_to_copy);
					}
					m = freelist;
					freelist = m->m_next;
					m->m_next = NULL;
					
					if ((m->m_flags & M_EXT))
						mlen = m->m_ext.ext_size;
					else if ((m->m_flags & M_PKTHDR))
						mlen = MHLEN - m_leadingspace(m);
					else
						mlen = MLEN;
					len = min(mlen, bytes_to_copy);

					chainlength += len;
					
					space -= len;

					error = uiomove(mtod(m, caddr_t), (int)len, uio);
		
					// LP64todo - fix this!
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
				
				} while (space > 0 && (chainlength < sosendmaxchain || atomic || resid < MINCLSIZE));
		
				socket_lock(so, 0);
	
				if (error)
					goto release;
			}
            
		    if (flags & (MSG_HOLD|MSG_SEND))
		    {
				/* Enqueue for later, go away if HOLD */
				register struct mbuf *mb1;
				if (so->so_temp && (flags & MSG_FLUSH))
				{
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
				if (flags & MSG_HOLD)
				{
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
			{
				struct socket_filter_entry *filter;
				int							filtered;
				
				filtered = 0;
				error = 0;
				for (filter = so->so_filt; filter && (error == 0);
					 filter = filter->sfe_next_onsocket) {
					if (filter->sfe_filter->sf_filter.sf_data_out) {
						int so_flags = 0;
						if (filtered == 0) {
							filtered = 1;
							so->so_send_filt_thread = current_thread();
							sflt_use(so);
							socket_unlock(so, 0);
							so_flags = (sendflags & MSG_OOB) ? sock_data_filt_flag_oob : 0;
						}
						error = filter->sfe_filter->sf_filter.sf_data_out(
									filter->sfe_cookie, so, addr, &top, &control, so_flags);
					}
				}
				
				if (filtered) {
					/*
					 * At this point, we've run at least one filter.
					 * The socket is unlocked as is the socket buffer.
					 */
					socket_lock(so, 0);
					sflt_unuse(so);
					so->so_send_filt_thread = 0;
					if (error) {
						if (error == EJUSTRETURN) {
							error = 0;
							clen = 0;
							control = 0;
							top = 0;
						}
						
						goto release;
					}
				}
			}
			/*
			 * End Socket filter processing
			 */
			
			if (error == EJUSTRETURN) {
				/* A socket filter handled this data */
				error = 0;
			}
			else {
				error = (*so->so_proto->pr_usrreqs->pru_send)(so,
							sendflags, top, addr, control, p);
			}
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

	KERNEL_DEBUG(DBG_FNC_SOSEND | DBG_FUNC_END,
		     so,
		     resid,
		     so->so_snd.sb_cc,
		     space,
		     error);

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
 */
int
soreceive(so, psa, uio, mp0, controlp, flagsp)
	register struct socket *so;
	struct sockaddr **psa;
	struct uio *uio;
	struct mbuf **mp0;
	struct mbuf **controlp;
	int *flagsp;
{
	register struct mbuf *m, **mp, *ml = NULL;
	register int flags, len, error, offset;
	struct protosw *pr = so->so_proto;
	struct mbuf *nextrecord;
	int moff, type = 0;
		// LP64todo - fix this!
	int orig_resid = uio_resid(uio);
	volatile struct mbuf *free_list;
	volatile int delayed_copy_len;
	int can_delay;
	int need_event;
	struct proc *p = current_proc();


		// LP64todo - fix this!
	KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_START,
		     so,
		     uio_resid(uio),
		     so->so_rcv.sb_cc,
		     so->so_rcv.sb_lowat,
		     so->so_rcv.sb_hiwat);

	socket_lock(so, 1);

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
			KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, ENOBUFS,0,0,0,0);
			return (ENOBUFS);
		}
		error = (*pr->pr_usrreqs->pru_rcvoob)(so, m, flags & MSG_PEEK);
		if (error)
			goto bad;
		socket_unlock(so, 0);
		do {
		// LP64todo - fix this!
			error = uiomove(mtod(m, caddr_t),
			    (int) min(uio_resid(uio), m->m_len), uio);
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
				 *  EWOULDBLOCK: out-of-band data not receive yet;
				 *  EINVAL: out-of-band data already read.
				 */
				error = 0;
				goto nooob;
			} else if (error == 0 && flagsp)
				*flagsp |= MSG_OOB;
		}	
		socket_unlock(so, 1);
		KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, error,0,0,0,0);
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
		printf("soreceive: sblock so=%x ref=%d on socket\n", so, so->so_usecount);
#endif
	error = sblock(&so->so_rcv, SBLOCKWAIT(flags));
	if (error) {
		socket_unlock(so, 1);
		KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, error,0,0,0,0);
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

		KASSERT(m != 0 || !so->so_rcv.sb_cc, ("receive 1"));
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
			if (m->m_type == MT_OOBDATA  || (m->m_flags & M_EOR)) {
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
		if ((so->so_state & SS_NBIO) || (flags & (MSG_DONTWAIT|MSG_NBIO))) {
			error = EWOULDBLOCK;
			goto release;
		}
		sbunlock(&so->so_rcv, 1);
#ifdef EVEN_MORE_LOCKING_DEBUG
		if (socket_debug)
		    printf("Waiting for socket data\n");
#endif

		error = sbwait(&so->so_rcv);
#ifdef EVEN_MORE_LOCKING_DEBUG
		if (socket_debug)
		    printf("SORECEIVE - sbwait returned %d\n", error);
#endif
		if (so->so_usecount < 1)
			panic("soreceive: after 2nd sblock so=%x ref=%d on socket\n", so, so->so_usecount);
		if (error) {
			socket_unlock(so, 1);
		    KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, error,0,0,0,0);
		    return (error);
		}
		goto restart;
	}
dontblock:
#ifndef __APPLE__
	if (uio->uio_procp)
		uio->uio_procp->p_stats->p_ru.ru_msgrcv++;
#else	/* __APPLE__ */
	/*
	 * 2207985
	 * This should be uio->uio-procp; however, some callers of this
	 * function use auto variables with stack garbage, and fail to
	 * fill out the uio structure properly.
	 */
	if (p)
		p->p_stats->p_ru.ru_msgrcv++;
#endif	/* __APPLE__ */
	nextrecord = m->m_nextpkt;
	if ((pr->pr_flags & PR_ADDR) && m->m_type == MT_SONAME) {
		KASSERT(m->m_type == MT_SONAME, ("receive 1a"));
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
				panic("soreceive: about to create invalid socketbuf");
			MFREE(m, so->so_rcv.sb_mb);
			m = so->so_rcv.sb_mb;
		}
	}
	while (m && m->m_type == MT_CONTROL && error == 0) {
		if (flags & MSG_PEEK) {
			if (controlp)
				*controlp = m_copy(m, 0, m->m_len);
			m = m->m_next;
		} else {
			sbfree(&so->so_rcv, m);
			if (controlp) {
				if (pr->pr_domain->dom_externalize &&
				    mtod(m, struct cmsghdr *)->cmsg_type ==
				    SCM_RIGHTS) {
				   socket_unlock(so, 0); /* release socket lock: see 3903171 */
				   error = (*pr->pr_domain->dom_externalize)(m);
				   socket_lock(so, 0);
				}
				*controlp = m;
				if (m->m_next == 0 && so->so_rcv.sb_cc != 0)
					panic("soreceive: so->so_rcv.sb_mb->m_next == 0 && so->so_rcv.sb_cc != 0");
				so->so_rcv.sb_mb = m->m_next;
				m->m_next = 0;
				m = so->so_rcv.sb_mb;
			} else {
				MFREE(m, so->so_rcv.sb_mb);
				m = so->so_rcv.sb_mb;
			}
		}
		if (controlp) {
			orig_resid = 0;
			controlp = &(*controlp)->m_next;
		}
	}
	if (m) {
		if ((flags & MSG_PEEK) == 0)
			m->m_nextpkt = nextrecord;
		type = m->m_type;
		if (type == MT_OOBDATA)
			flags |= MSG_OOB;
	}
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
		} else if (type == MT_OOBDATA)
			break;
#ifndef __APPLE__
/*
 * This assertion needs rework.  The trouble is Appletalk is uses many
 * mbuf types (NOT listed in mbuf.h!) which will trigger this panic.
 * For now just remove the assertion...  CSM 9/98
 */
		else
		    KASSERT(m->m_type == MT_DATA || m->m_type == MT_HEADER,
			("receive 3"));
#else
		/*
		 * Make sure to allways set MSG_OOB event when getting 
		 * out of band data inline.
		 */
		if ((so->so_options & SO_WANTOOBFLAG) != 0 &&
			(so->so_options & SO_OOBINLINE) != 0 && 
			(so->so_state & SS_RCVATMARK) != 0) {
			flags |= MSG_OOB;
		}
#endif
		so->so_state &= ~SS_RCVATMARK;
		// LP64todo - fix this!
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
			if (can_delay && len == m->m_len) {
			        /*
				 * only delay the copy if we're consuming the
				 * mbuf and we're NOT in MSG_PEEK mode
				 * and we have enough data to make it worthwile
				 * to drop and retake the funnel... can_delay
				 * reflects the state of the 2 latter constraints
				 * moff should always be zero in these cases
				 */
			        delayed_copy_len += len;
			} else {

  			        if (delayed_copy_len) {
				        error = sodelayed_copy(so, uio, &free_list, &delayed_copy_len);

					if (error) {
						goto release;
					}
					if (m != so->so_rcv.sb_mb) {
					        /*
						 * can only get here if MSG_PEEK is not set
						 * therefore, m should point at the head of the rcv queue...
						 * if it doesn't, it means something drastically changed
						 * while we were out from behind the funnel in sodelayed_copy...
						 * perhaps a RST on the stream... in any event, the stream has
						 * been interrupted... it's probably best just to return 
						 * whatever data we've moved and let the caller sort it out...
						 */
					        break;
					}
				}
				socket_unlock(so, 0);
				error = uiomove(mtod(m, caddr_t) + moff, (int)len, uio);
				socket_lock(so, 0);

				if (error)
				        goto release;
			}
		} else
			uio_setresid(uio, (uio_resid(uio) - len));

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
				if (m)
					m->m_nextpkt = nextrecord;
			}
		} else {
			if (flags & MSG_PEEK)
				moff += len;
			else {
				if (mp)
					*mp = m_copym(m, 0, len, M_WAIT);
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
				     * delay posting the actual event until after
				     * any delayed copy processing has finished
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
		 * If the MSG_WAITALL or MSG_WAITSTREAM flag is set (for non-atomic socket),
		 * we must not quit until "uio->uio_resid == 0" or an error
		 * termination.  If a signal/timeout occurs, return
		 * with a short count but without error.
		 * Keep sockbuf locked against other readers.
		 */
		while (flags & (MSG_WAITALL|MSG_WAITSTREAM) && m == 0 && (uio_resid(uio) - delayed_copy_len) > 0 &&
		    !sosendallatonce(so) && !nextrecord) {
			if (so->so_error || so->so_state & SS_CANTRCVMORE)
			        goto release;

		        if (pr->pr_flags & PR_WANTRCVD && so->so_pcb && (((struct inpcb *)so->so_pcb)->inp_state != INPCB_STATE_DEAD))
			        (*pr->pr_usrreqs->pru_rcvd)(so, flags);
			if (sbwait(&so->so_rcv)) {
			        error = 0;
				goto release;
			}
			/*
			 * have to wait until after we get back from the sbwait to do the copy because
			 * we will drop the funnel if we have enough data that has been delayed... by dropping
			 * the funnel we open up a window allowing the netisr thread to process the incoming packets
			 * and to change the state of this socket... we're issuing the sbwait because
			 * the socket is empty and we're expecting the netisr thread to wake us up when more
			 * packets arrive... if we allow that processing to happen and then sbwait, we
			 * could stall forever with packets sitting in the socket if no further packets
			 * arrive from the remote side.
			 *
			 * we want to copy before we've collected all the data to satisfy this request to 
			 * allow the copy to overlap the incoming packet processing on an MP system
			 */
			if (delayed_copy_len > sorecvmincopy && (delayed_copy_len > (so->so_rcv.sb_hiwat / 2))) {

			        error = sodelayed_copy(so, uio, &free_list, &delayed_copy_len);

				if (error)
				        goto release;
			}
			m = so->so_rcv.sb_mb;
			if (m) {
				nextrecord = m->m_nextpkt;
			}
		}
	}
#ifdef MORE_LOCKING_DEBUG
	if (so->so_usecount <= 1)
		panic("soreceive: after big while so=%x ref=%d on socket\n", so, so->so_usecount);
#endif

	if (m && pr->pr_flags & PR_ATOMIC) {
#ifdef __APPLE__
		if (so->so_options & SO_DONTTRUNC)
			flags |= MSG_RCVMORE;
		else {
#endif
			flags |= MSG_TRUNC;
			if ((flags & MSG_PEEK) == 0)
				(void) sbdroprecord(&so->so_rcv);
#ifdef __APPLE__
		}
#endif
	}
	if ((flags & MSG_PEEK) == 0) {
		if (m == 0)
			so->so_rcv.sb_mb = nextrecord;
		if (pr->pr_flags & PR_WANTRCVD && so->so_pcb)
			(*pr->pr_usrreqs->pru_rcvd)(so, flags);
	}
#ifdef __APPLE__
	if ((so->so_options & SO_WANTMORE) && so->so_rcv.sb_cc > 0)
		flags |= MSG_HAVEMORE;

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
		panic("soreceive: release so=%x ref=%d on socket\n", so, so->so_usecount);
#endif
	if (delayed_copy_len) {
	        error = sodelayed_copy(so, uio, &free_list, &delayed_copy_len);
	}
	if (free_list) {
	        m_freem_list((struct mbuf *)free_list);
	}
	sbunlock(&so->so_rcv, 0);	/* will unlock socket */

		// LP64todo - fix this!
	KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END,
		     so,
		     uio_resid(uio),
		     so->so_rcv.sb_cc,
		     0,
		     error);

	return (error);
}


static int sodelayed_copy(struct socket *so, struct uio *uio, struct mbuf **free_list, int *resid)
{
        int         error  = 0;
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


int
soshutdown(so, how)
	register struct socket *so;
	register int how;
{
	register struct protosw *pr = so->so_proto;
	int ret;

	socket_lock(so, 1);
	
	sflt_notify(so, sock_evt_shutdown, &how);

	if (how != SHUT_WR) {
		sorflush(so);
		postevent(so, 0, EV_RCLOSED);
	}
	if (how != SHUT_RD) {
	    ret = ((*pr->pr_usrreqs->pru_shutdown)(so));
	    postevent(so, 0, EV_WCLOSED);
	    KERNEL_DEBUG(DBG_FNC_SOSHUTDOWN | DBG_FUNC_END, 0,0,0,0,0);
		socket_unlock(so, 1);
	    return(ret);
	}

	KERNEL_DEBUG(DBG_FNC_SOSHUTDOWN | DBG_FUNC_END, 0,0,0,0,0);
	socket_unlock(so, 1);
	return (0);
}

void
sorflush(so)
	register struct socket *so;
{
	register struct sockbuf *sb = &so->so_rcv;
	register struct protosw *pr = so->so_proto;
	struct sockbuf asb;

#ifdef MORE_LOCKING_DEBUG
	lck_mtx_t * mutex_held;

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
	if (pr->pr_flags & PR_RIGHTS && pr->pr_domain->dom_dispose)
		(*pr->pr_domain->dom_dispose)(asb.sb_mb);
	sbrelease(&asb);
}

/*
 * Perhaps this routine, and sooptcopyout(), below, ought to come in
 * an additional variant to handle the case where the option value needs
 * to be some kind of integer, but not a specific size.
 * In addition to their use here, these functions are also called by the
 * protocol-level pr_ctloutput() routines.
 */
int
sooptcopyin(sopt, buf, len, minlen)
	struct	sockopt *sopt;
	void	*buf;
	size_t	len;
	size_t	minlen;
{
	size_t	valsize;

	/*
	 * If the user gives us more than we wanted, we ignore it,
	 * but if we don't get the minimum length the caller
	 * wants, we return EINVAL.  On success, sopt->sopt_valsize
	 * is set to however much we actually retrieved.
	 */
	if ((valsize = sopt->sopt_valsize) < minlen)
		return EINVAL;
	if (valsize > len)
		sopt->sopt_valsize = valsize = len;

	if (sopt->sopt_p != 0)
		return (copyin(sopt->sopt_val, buf, valsize));

	bcopy(CAST_DOWN(caddr_t, sopt->sopt_val), buf, valsize);
	return 0;
}

int
sosetopt(so, sopt)
	struct socket *so;
	struct sockopt *sopt;
{
	int	error, optval;
	struct	linger l;
	struct	timeval tv;
	short	val;

	socket_lock(so, 1);

	if (sopt->sopt_dir != SOPT_SET) {
		sopt->sopt_dir = SOPT_SET;
	}

	{
		struct socket_filter_entry	*filter;
		int						 	filtered = 0;
		error = 0;
		for (filter = so->so_filt; filter && (error == 0);
			 filter = filter->sfe_next_onsocket) {
			if (filter->sfe_filter->sf_filter.sf_setoption) {
				if (filtered == 0) {
					filtered = 1;
					sflt_use(so);
					socket_unlock(so, 0);
				}
				error = filter->sfe_filter->sf_filter.sf_setoption(
							filter->sfe_cookie, so, sopt);
			}
		}
		
		if (filtered != 0) {
			socket_lock(so, 0);
			sflt_unuse(so);
			
			if (error) {
				if (error == EJUSTRETURN)
					error = 0;
				goto bad;
			}
		}
	}

	error = 0;
	if (sopt->sopt_level != SOL_SOCKET) {
		if (so->so_proto && so->so_proto->pr_ctloutput) {
			error = (*so->so_proto->pr_ctloutput)
				  (so, sopt);
			socket_unlock(so, 1);
			return (error);
		}
		error = ENOPROTOOPT;
	} else {
		switch (sopt->sopt_name) {
		case SO_LINGER:
		case SO_LINGER_SEC:
			error = sooptcopyin(sopt, &l, sizeof l, sizeof l);
			if (error)
				goto bad;

			so->so_linger = (sopt->sopt_name == SO_LINGER) ? l.l_linger : l.l_linger * hz;
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
#ifdef __APPLE__
		case SO_DONTTRUNC:
		case SO_WANTMORE:
		case SO_WANTOOBFLAG:
#endif
			error = sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
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
			error = sooptcopyin(sopt, &optval, sizeof optval,
					    sizeof optval);
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
				if (sbreserve(sopt->sopt_name == SO_SNDBUF ?
					      &so->so_snd : &so->so_rcv,
					      (u_long) optval) == 0) {
					error = ENOBUFS;
					goto bad;
				}
				break;

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
			error = sooptcopyin(sopt, &tv, sizeof tv,
					    sizeof tv);
			if (error)
				goto bad;

			if (tv.tv_sec < 0 || tv.tv_sec > LONG_MAX ||
			    tv.tv_usec < 0 || tv.tv_usec >= 1000000) {
				error = EDOM;
				goto bad;
			}
			
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

			error = sooptcopyin(sopt, &nke,
								sizeof nke, sizeof nke);
			if (error)
			  goto bad;

			error = sflt_attach_private(so, NULL, nke.nke_handle, 1);
			break;
		}

		case SO_NOSIGPIPE:
                        error = sooptcopyin(sopt, &optval, sizeof optval,
                                            sizeof optval);
                        if (error)
                                goto bad;
                        if (optval)
                                so->so_flags |= SOF_NOSIGPIPE;
                        else
                                so->so_flags &= ~SOF_NOSIGPIPE;
			
			break;

		case SO_NOADDRERR:
                        error = sooptcopyin(sopt, &optval, sizeof optval,
                                            sizeof optval);
                        if (error)
                                goto bad;
                        if (optval)
                                so->so_flags |= SOF_NOADDRAVAIL;
                        else
                                so->so_flags &= ~SOF_NOADDRAVAIL;
			
			break;

		default:
			error = ENOPROTOOPT;
			break;
		}
		if (error == 0 && so->so_proto && so->so_proto->pr_ctloutput) {
			(void) ((*so->so_proto->pr_ctloutput)
				  (so, sopt));
		}
	}
bad:
	socket_unlock(so, 1);
	return (error);
}

/* Helper routine for getsockopt */
int
sooptcopyout(sopt, buf, len)
	struct	sockopt *sopt;
	void	*buf;
	size_t	len;
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
		if (sopt->sopt_p != 0)
			error = copyout(buf, sopt->sopt_val, valsize);
		else
			bcopy(buf, CAST_DOWN(caddr_t, sopt->sopt_val), valsize);
	}
	return error;
}

int
sogetopt(so, sopt)
	struct socket *so;
	struct sockopt *sopt;
{
	int	error, optval;
	struct	linger l;
	struct	timeval tv;

        if (sopt->sopt_dir != SOPT_GET) {
                sopt->sopt_dir = SOPT_GET;
        }

	socket_lock(so, 1);
	
	{
		struct socket_filter_entry	*filter;
		int						 	filtered = 0;
		error = 0;
		for (filter = so->so_filt; filter && (error == 0);
			 filter = filter->sfe_next_onsocket) {
			if (filter->sfe_filter->sf_filter.sf_getoption) {
				if (filtered == 0) {
					filtered = 1;
					sflt_use(so);
					socket_unlock(so, 0);
				}
				error = filter->sfe_filter->sf_filter.sf_getoption(
							filter->sfe_cookie, so, sopt);
			}
		}
		if (filtered != 0) {
			socket_lock(so, 0);
			sflt_unuse(so);
			
			if (error) {
				if (error == EJUSTRETURN)
					error = 0;
				socket_unlock(so, 1);
				return error;
			}
		}
	}

	error = 0;
	if (sopt->sopt_level != SOL_SOCKET) {
		if (so->so_proto && so->so_proto->pr_ctloutput) {
			error = (*so->so_proto->pr_ctloutput)
				  (so, sopt);
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
			l.l_linger = (sopt->sopt_name == SO_LINGER) ? so->so_linger : 
				so->so_linger / hz;
			error = sooptcopyout(sopt, &l, sizeof l);
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
#ifdef __APPLE__
		case SO_DONTTRUNC:
		case SO_WANTMORE:
		case SO_WANTOOBFLAG:
#endif
			optval = so->so_options & sopt->sopt_name;
integer:
			error = sooptcopyout(sopt, &optval, sizeof optval);
			break;

		case SO_TYPE:
			optval = so->so_type;
			goto integer;

#ifdef __APPLE__
		case SO_NREAD:
		{
			int pkt_total;
			struct mbuf *m1;

			pkt_total = 0;
			m1 = so->so_rcv.sb_mb;
		  	if (so->so_proto->pr_flags & PR_ATOMIC)
			{
				while (m1) {
					if (m1->m_type == MT_DATA)
						pkt_total += m1->m_len;
					m1 = m1->m_next;
				}
				optval = pkt_total;
			} else
				optval = so->so_rcv.sb_cc;
			goto integer;
		}
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

			error = sooptcopyout(sopt, &tv, sizeof tv);
			break;			

		case SO_NOSIGPIPE:
			optval = (so->so_flags & SOF_NOSIGPIPE);
			goto integer;

		case SO_NOADDRERR:
			optval = (so->so_flags & SOF_NOADDRAVAIL);
			goto integer;

		default:
			error = ENOPROTOOPT;
			break;
		}
		socket_unlock(so, 1);
		return (error);
	}
}

/* XXX; prepare mbuf for (__FreeBSD__ < 3) routines. */
int
soopt_getm(struct sockopt *sopt, struct mbuf **mp)
{
	struct mbuf *m, *m_prev;
	int sopt_size = sopt->sopt_valsize;

	if (sopt_size > MAX_SOOPTGETM_SIZE)
		return EMSGSIZE;

	MGET(m, sopt->sopt_p ? M_WAIT : M_DONTWAIT, MT_DATA);
	if (m == 0)
		return ENOBUFS;
	if (sopt_size > MLEN) {
		MCLGET(m, sopt->sopt_p ? M_WAIT : M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			return ENOBUFS;
		}
		m->m_len = min(MCLBYTES, sopt_size);
	} else {
		m->m_len = min(MLEN, sopt_size);
	}
	sopt_size -= m->m_len;
	*mp = m;
	m_prev = m;

	while (sopt_size) {
		MGET(m, sopt->sopt_p ? M_WAIT : M_DONTWAIT, MT_DATA);
		if (m == 0) {
			m_freem(*mp);
			return ENOBUFS;
		}
		if (sopt_size > MLEN) {
			MCLGET(m, sopt->sopt_p ? M_WAIT : M_DONTWAIT);
			if ((m->m_flags & M_EXT) == 0) {
				m_freem(*mp);
				return ENOBUFS;
			}
			m->m_len = min(MCLBYTES, sopt_size);
		} else {
			m->m_len = min(MLEN, sopt_size);
		}
		sopt_size -= m->m_len;
		m_prev->m_next = m;
		m_prev = m;
	}
	return 0;
}

/* XXX; copyin sopt data into mbuf chain for (__FreeBSD__ < 3) routines. */
int
soopt_mcopyin(struct sockopt *sopt, struct mbuf *m)
{
	struct mbuf *m0 = m;

	if (sopt->sopt_val == USER_ADDR_NULL)
		return 0;
	while (m != NULL && sopt->sopt_valsize >= m->m_len) {
		if (sopt->sopt_p != NULL) {
			int error;

			error = copyin(sopt->sopt_val, mtod(m, char *), m->m_len);
			if (error != 0) {
				m_freem(m0);
				return(error);
			}
		} else
			bcopy(CAST_DOWN(caddr_t, sopt->sopt_val), mtod(m, char *), m->m_len);
		sopt->sopt_valsize -= m->m_len;
		sopt->sopt_val += m->m_len; 
		m = m->m_next;
	}
	if (m != NULL) /* should be allocated enoughly at ip6_sooptmcopyin() */
		panic("soopt_mcopyin");
	return 0;
}

/* XXX; copyout mbuf chain data into soopt for (__FreeBSD__ < 3) routines. */
int
soopt_mcopyout(struct sockopt *sopt, struct mbuf *m)
{
	struct mbuf *m0 = m;
	size_t valsize = 0;

	if (sopt->sopt_val == USER_ADDR_NULL)
		return 0;
	while (m != NULL && sopt->sopt_valsize >= m->m_len) {
		if (sopt->sopt_p != NULL) {
			int error;

			error = copyout(mtod(m, char *), sopt->sopt_val, m->m_len);
			if (error != 0) {
				m_freem(m0);
				return(error);
			}
		} else
			bcopy(mtod(m, char *), CAST_DOWN(caddr_t, sopt->sopt_val), m->m_len);
	       sopt->sopt_valsize -= m->m_len;
	       sopt->sopt_val += m->m_len;
	       valsize += m->m_len;
	       m = m->m_next;
	}
	if (m != NULL) {
		/* enough soopt buffer should be given from user-land */
		m_freem(m0);
		return(EINVAL);
	}
	sopt->sopt_valsize = valsize;
	return 0;
}

void
sohasoutofband(so)
	register struct socket *so;
{
	struct proc *p;

	if (so->so_pgid < 0)
		gsignal(-so->so_pgid, SIGURG);
	else if (so->so_pgid > 0 && (p = pfind(so->so_pgid)) != 0)
		psignal(p, SIGURG);
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
			/* Darwin sets the flag first, BSD calls selrecord first */
			so->so_rcv.sb_flags |= SB_SEL;
			selrecord(p, &so->so_rcv.sb_sel, wql);
		}

		if (events & (POLLOUT | POLLWRNORM)) {
			/* Darwin sets the flag first, BSD calls selrecord first */
			so->so_snd.sb_flags |= SB_SEL;
			selrecord(p, &so->so_snd.sb_sel, wql);
		}
	}

	socket_unlock(so, 1);
	return (revents);
}

int     soo_kqfilter(struct fileproc *fp, struct knote *kn, struct proc *p);

int
soo_kqfilter(__unused struct fileproc *fp, struct knote *kn, __unused struct proc *p)
{
	struct socket *so = (struct socket *)kn->kn_fp->f_fglob->fg_data;
	struct sockbuf *sb;
	socket_lock(so, 1);

	switch (kn->kn_filter) {
	case EVFILT_READ:
		if (so->so_options & SO_ACCEPTCONN)
			kn->kn_fop = &solisten_filtops;
		else
			kn->kn_fop = &soread_filtops;
		sb = &so->so_rcv;
		break;
	case EVFILT_WRITE:
		kn->kn_fop = &sowrite_filtops;
		sb = &so->so_snd;
		break;
	default:
		socket_unlock(so, 1);
		return (1);
	}

	if (KNOTE_ATTACH(&sb->sb_sel.si_note, kn))
		sb->sb_flags |= SB_KNOTE;
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

	if (so->so_oobmark) {
		if (kn->kn_flags & EV_OOBAND) {
			kn->kn_data = so->so_rcv.sb_cc - so->so_oobmark;
			if ((hint & SO_FILT_HINT_LOCKED) == 0)
				socket_unlock(so, 1);
			return (1);
		}
		kn->kn_data = so->so_oobmark;
		kn->kn_flags |= EV_OOBAND;
	} else {
		kn->kn_data = so->so_rcv.sb_cc;
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

	if ((hint & SO_FILT_HINT_LOCKED) == 0)
		socket_unlock(so, 1);

	return( kn->kn_flags & EV_OOBAND ||
	        kn->kn_data >= ((kn->kn_sfflags & NOTE_LOWAT) ? 
	                        kn->kn_sdata : so->so_rcv.sb_lowat));
}

static void
filt_sowdetach(struct knote *kn)
{
	struct socket *so = (struct socket *)kn->kn_fp->f_fglob->fg_data;
	socket_lock(so, 1);

	if(so->so_snd.sb_flags & SB_KNOTE)
		if (KNOTE_DETACH(&so->so_snd.sb_sel.si_note, kn))
			so->so_snd.sb_flags &= ~SB_KNOTE;
	socket_unlock(so, 1);
}

/*ARGSUSED*/
static int
filt_sowrite(struct knote *kn, long hint)
{
	struct socket *so = (struct socket *)kn->kn_fp->f_fglob->fg_data;

	if ((hint & SO_FILT_HINT_LOCKED) == 0)
		socket_lock(so, 1);

	kn->kn_data = sbspace(&so->so_snd);
	if (so->so_state & SS_CANTSENDMORE) {
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
	if (((so->so_state & SS_ISCONNECTED) == 0) &&
	    (so->so_proto->pr_flags & PR_CONNREQUIRED)) {
		if ((hint & SO_FILT_HINT_LOCKED) == 0)
			socket_unlock(so, 1);
		return (0);
	}
	if ((hint & SO_FILT_HINT_LOCKED) == 0)
		socket_unlock(so, 1);
	if (kn->kn_sfflags & NOTE_LOWAT)
		return (kn->kn_data >= kn->kn_sdata);
	return (kn->kn_data >= so->so_snd.sb_lowat);
}

/*ARGSUSED*/
static int
filt_solisten(struct knote *kn, long hint)
{
	struct socket *so = (struct socket *)kn->kn_fp->f_fglob->fg_data;
	int isempty;

	if ((hint & SO_FILT_HINT_LOCKED) == 0)
		socket_lock(so, 1);
	kn->kn_data = so->so_qlen;
	isempty = ! TAILQ_EMPTY(&so->so_comp);
	if ((hint & SO_FILT_HINT_LOCKED) == 0)
		socket_unlock(so, 1);
	return (isempty);
}


int
socket_lock(so, refcount)
	struct socket *so;
	int refcount;
{
	int error = 0, lr, lr_saved;
#ifdef __ppc__
	__asm__ volatile("mflr %0" : "=r" (lr));
        lr_saved = lr;
#endif 

	if (so->so_proto->pr_lock) {
		error = (*so->so_proto->pr_lock)(so, refcount, lr_saved);
	}
	else {
#ifdef MORE_LOCKING_DEBUG
		lck_mtx_assert(so->so_proto->pr_domain->dom_mtx, LCK_MTX_ASSERT_NOTOWNED);
#endif
		lck_mtx_lock(so->so_proto->pr_domain->dom_mtx);
		if (refcount)
			so->so_usecount++;
		so->reserved3 = (void*)lr_saved; /* save caller for refcount going to zero */
	}

	return(error);

}

int
socket_unlock(so, refcount)
	struct socket *so;
	int refcount;
{
	int error = 0, lr, lr_saved;
	lck_mtx_t * mutex_held;

#ifdef __ppc__
__asm__ volatile("mflr %0" : "=r" (lr));
        lr_saved = lr;
#endif



	if (so->so_proto == NULL)
		panic("socket_unlock null so_proto so=%x\n", so);

	if (so && so->so_proto->pr_unlock) 
		error = (*so->so_proto->pr_unlock)(so, refcount, lr_saved);
	else {
		mutex_held = so->so_proto->pr_domain->dom_mtx;
#ifdef MORE_LOCKING_DEBUG
		lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
#endif
		if (refcount) {
			if (so->so_usecount <= 0)
				panic("socket_unlock: bad refcount so=%x value=%d\n", so, so->so_usecount);
			so->so_usecount--;
			if (so->so_usecount == 0) {
				sofreelastref(so, 1);
			}
			else 
				so->reserved4 = (void*)lr_saved; /* save caller */
		}
		lck_mtx_unlock(mutex_held);
	}

	return(error);
}
//### Called with socket locked, will unlock socket
void
sofree(so) 
	struct socket *so;
{

	int lr, lr_saved;
	lck_mtx_t * mutex_held;
#ifdef __ppc__
	__asm__ volatile("mflr %0" : "=r" (lr));
	lr_saved = lr;
#endif
	if (so->so_proto->pr_getlock != NULL)  
		mutex_held = (*so->so_proto->pr_getlock)(so, 0);
	else  
		mutex_held = so->so_proto->pr_domain->dom_mtx;
	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
	
	sofreelastref(so, 0);
}

void
soreference(so)
	struct socket *so;
{
	socket_lock(so, 1);	/* locks & take one reference on socket */
	socket_unlock(so, 0);	/* unlock only */
}

void
sodereference(so)
	struct socket *so;
{
	socket_lock(so, 0);
	socket_unlock(so, 1);
}
