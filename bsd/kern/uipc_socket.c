/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
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
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/kernel.h>
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

#include <machine/limits.h>

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


SYSCTL_DECL(_kern_ipc);

static int somaxconn = SOMAXCONN;
SYSCTL_INT(_kern_ipc, KIPC_SOMAXCONN, somaxconn, CTLFLAG_RW, &somaxconn,
	   0, "");

/* Should we get a maximum also ??? */
static int sosendmaxchain = 65536;
static int sosendminchain = 16384;
SYSCTL_INT(_kern_ipc, OID_AUTO, sosendminchain, CTLFLAG_RW, &sosendminchain,
           0, "");

void  so_cache_timer();
struct mbuf *m_getpackets(int, int, int);


/*
 * Socket operation routines.
 * These routines are called by the routines in
 * sys_socket.c or from a system process, and
 * implement the semantics of socket operations by
 * switching out to the protocol specific routines.
 */

#ifdef __APPLE__
void socketinit()
{
    vm_size_t	str_size;

    so_cache_init_done = 1;

    timeout(so_cache_timer, NULL, (SO_CACHE_FLUSH_INTERVAL * hz));
    str_size = (vm_size_t)( sizeof(struct socket) + 4 +
			    get_inpcb_str_size()  + 4 +
			    get_tcp_str_size());
    so_cache_zone = zinit (str_size, 120000*str_size, 8192, "socache zone");
#if TEMPDEBUG
    kprintf("cached_sock_alloc -- so_cache_zone size is %x\n", str_size);
#endif

}

void   cached_sock_alloc(so, waitok)
struct socket **so;
int           waitok;

{
    caddr_t	temp;
    int		s;
    register u_long  offset;


    s = splnet(); 
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
	    splx(s); 

	    temp = (*so)->so_saved_pcb;
	    bzero((caddr_t)*so, sizeof(struct socket));
#if TEMPDEBUG
	    kprintf("cached_sock_alloc - retreiving cached sock %x - count == %d\n", *so,
		   cached_sock_count);
#endif
	    (*so)->so_saved_pcb = temp;
    }
    else {
#if TEMPDEBUG
	    kprintf("Allocating cached sock %x from memory\n", *so);
#endif

	    splx(s); 
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
	int   s;


    	s = splnet(); 
	if (++cached_sock_count > MAX_CACHED_SOCKETS) {
		--cached_sock_count;
		splx(s); 
#if TEMPDEBUG
		kprintf("Freeing overflowed cached socket %x\n", so);
#endif
		zfree(so_cache_zone, (vm_offset_t) so);
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
		splx(s); 
	}

#if TEMPDEBUG
	kprintf("Freed cached sock %x into cache - count is %d\n", so, cached_sock_count);
#endif


}


void so_cache_timer()
{
	register struct socket	*p;
	register int		s;
	register int		n_freed = 0;
	boolean_t 	funnel_state;

	funnel_state = thread_funnel_set(network_flock, TRUE);

	++so_cache_time;

	s = splnet();

	while (p = socket_cache_tail)
	{
		if ((so_cache_time - p->cache_timestamp) < SO_CACHE_TIME_LIMIT)
		        break;

		so_cache_timeouts++;
		
		if (socket_cache_tail = p->cache_prev)
		        p->cache_prev->cache_next = 0;
		if (--cached_sock_count == 0)
		        socket_cache_head = 0;

		splx(s);

		zfree(so_cache_zone, (vm_offset_t) p);
		
		splnet();
		if (++n_freed >= SO_CACHE_MAX_FREE_BATCH)
		{
		        so_cache_max_freed++;
			break;
		}
	}
	splx(s);

	timeout(so_cache_timer, NULL, (SO_CACHE_FLUSH_INTERVAL * hz));

	(void) thread_funnel_set(network_flock, FALSE);

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
	     so = _MALLOC_ZONE(sizeof(*so), socket_zone, M_WAITOK);
	     if (so) 
		  bzero(so, sizeof *so);
	}
	/* XXX race condition for reentrant kernel */

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
		if (p->p_ucred->cr_uid == 0)
			so->so_state = SS_PRIV;

		so->so_uid = p->p_ucred->cr_uid;
	}
#else
	so->so_cred = p->p_ucred;
	crhold(so->so_cred);
#endif
	so->so_proto = prp;
#ifdef __APPLE__
	so->so_rcv.sb_flags |= SB_RECV;	/* XXX */
	if (prp->pr_sfilter.tqh_first)
		error = sfilter_init(so);
	if (error == 0)
#endif
		error = (*prp->pr_usrreqs->pru_attach)(so, proto, p);
	if (error) {
		so->so_state |= SS_NOFDREF;
		sofree(so);
		return (error);
	}
#ifdef __APPLE__
	prp->pr_domain->dom_refs++;
	so->so_rcv.sb_so = so->so_snd.sb_so = so;
	TAILQ_INIT(&so->so_evlist);
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
	int error;
	struct kextcb *kp;
	int s = splnet();

	error = (*so->so_proto->pr_usrreqs->pru_bind)(so, nam, p);
	if (error == 0) {
		kp = sotokextcb(so);
		while (kp) {
			if (kp->e_soif && kp->e_soif->sf_sobind) {
				error = (*kp->e_soif->sf_sobind)(so, nam, kp);
				if (error) {
					if (error == EJUSTRETURN) {
						error = 0;
						break;
					}
					splx(s);
					return(error);
				}
			}
			kp = kp->e_next;
		}
	}
	splx(s);
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
	crfree(so->so_cred);
	zfreei(so->so_zone, so);
#else
	if (so->cached_in_sock_layer == 1) 
	     cached_sock_free(so);
	else
	     _FREE_ZONE(so, sizeof(*so), so->so_zone);
#endif /* __APPLE__ */
}

int
solisten(so, backlog)
	register struct socket *so;
	int backlog;

{
	struct kextcb *kp;
	struct proc *p = current_proc();
	int s, error;

	s = splnet();
	error = (*so->so_proto->pr_usrreqs->pru_listen)(so, p);
	if (error) {
		splx(s);
		return (error);
	}
        if (TAILQ_EMPTY(&so->so_comp))
		so->so_options |= SO_ACCEPTCONN;
	if (backlog < 0 || backlog > somaxconn)
		backlog = somaxconn;
	so->so_qlimit = backlog;
	kp = sotokextcb(so);
	while (kp) {	
		if (kp->e_soif && kp->e_soif->sf_solisten) {
			error = (*kp->e_soif->sf_solisten)(so, kp);
			if (error) {
				if (error == EJUSTRETURN) {
					error = 0;
					break;
				}
				splx(s);
				return(error);
			}
		}
		kp = kp->e_next;
	}

	splx(s);
	return (0);
}


void
sofree(so)
	register struct socket *so;
{
	int error;
	struct kextcb *kp;
	struct socket *head = so->so_head;

	kp = sotokextcb(so);
	while (kp) {
		if (kp->e_soif && kp->e_soif->sf_sofree) {
			error = (*kp->e_soif->sf_sofree)(so, kp);
			if (error) {
				selthreadclear(&so->so_snd.sb_sel);
				selthreadclear(&so->so_rcv.sb_sel);
				return;	/* void fn */
			}
		}
		kp = kp->e_next;
	}

	if (so->so_pcb || (so->so_state & SS_NOFDREF) == 0) {
#ifdef __APPLE__
		selthreadclear(&so->so_snd.sb_sel);
		selthreadclear(&so->so_rcv.sb_sel);
#endif
		return;
	}
	if (head != NULL) {
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
#endif
			return;
		} else {
			panic("sofree: not queued");
		}
		head->so_qlen--;
		so->so_state &= ~SS_INCOMP;
		so->so_head = NULL;
	}
#ifdef __APPLE__
	selthreadclear(&so->so_snd.sb_sel);
	sbrelease(&so->so_snd);
#endif
	sorflush(so);
	sfilter_term(so);
	sodealloc(so);
}

/*
 * Close a socket on last file table reference removal.
 * Initiate disconnect if connected.
 * Free socket when disconnect complete.
 */
int
soclose(so)
	register struct socket *so;
{
	int s = splnet();		/* conservative */
	int error = 0;
	struct kextcb *kp;

#ifndef __APPLE__
	funsetown(so->so_sigio);
#endif
	kp = sotokextcb(so);
	while (kp) {
		if (kp->e_soif && kp->e_soif->sf_soclose) {
			error = (*kp->e_soif->sf_soclose)(so, kp);
			if (error) {
				splx(s);
				return((error == EJUSTRETURN) ? 0 : error);
			}
		}
		kp = kp->e_next;
	}

	if (so->so_options & SO_ACCEPTCONN) {
		struct socket *sp, *sonext;

                sp = TAILQ_FIRST(&so->so_incomp);
                for (; sp != NULL; sp = sonext) {
                        sonext = TAILQ_NEXT(sp, so_list);
                        (void) soabort(sp);
                }
                for (sp = TAILQ_FIRST(&so->so_comp); sp != NULL; sp = sonext) {
                        sonext = TAILQ_NEXT(sp, so_list);
                        /* Dequeue from so_comp since sofree() won't do it */
                        TAILQ_REMOVE(&so->so_comp, sp, so_list);
                        so->so_qlen--;
                        sp->so_state &= ~SS_COMP;
                        sp->so_head = NULL;
                        (void) soabort(sp);
                }

	}
	if (so->so_pcb == 0)
		goto discard;
	if (so->so_state & SS_ISCONNECTED) {
		if ((so->so_state & SS_ISDISCONNECTING) == 0) {
			error = sodisconnect(so);
			if (error)
				goto drop;
		}
		if (so->so_options & SO_LINGER) {
			if ((so->so_state & SS_ISDISCONNECTING) &&
			    (so->so_state & SS_NBIO))
				goto drop;
			while (so->so_state & SS_ISCONNECTED) {
				error = tsleep((caddr_t)&so->so_timeo,
				    PSOCK | PCATCH, "soclos", so->so_linger);
				if (error)
					break;
			}
		}
	}
drop:
	if (so->so_pcb) {
		int error2 = (*so->so_proto->pr_usrreqs->pru_detach)(so);
		if (error == 0)
			error = error2;
	}
discard:
	if (so->so_pcb && so->so_state & SS_NOFDREF)
		panic("soclose: NOFDREF");
	so->so_state |= SS_NOFDREF;
#ifdef __APPLE__
	so->so_proto->pr_domain->dom_refs--;
	evsofree(so);
#endif
	sofree(so);
	splx(s);
	return (error);
}

/*
 * Must be called at splnet...
 */
int
soabort(so)
	struct socket *so;
{
	int error;

	error = (*so->so_proto->pr_usrreqs->pru_abort)(so);
	if (error) {
		sofree(so);
		return error;
	}
	return (0);
}

int
soaccept(so, nam)
	register struct socket *so;
	struct sockaddr **nam;
{
	int s = splnet();
	int error;
	struct kextcb *kp;

	if ((so->so_state & SS_NOFDREF) == 0)
		panic("soaccept: !NOFDREF");
	so->so_state &= ~SS_NOFDREF;
	error = (*so->so_proto->pr_usrreqs->pru_accept)(so, nam);
	if (error == 0) {
		kp = sotokextcb(so);
		while (kp) {
			if (kp->e_soif && kp->e_soif->sf_soaccept) {
				error = (*kp->e_soif->sf_soaccept)(so, nam, kp);
				if (error) {
					if (error == EJUSTRETURN) {
						error = 0;
						break;
					}
					splx(s);
					return(error);
				}
			}
			kp = kp->e_next;
		}
	}
    
    
	splx(s);
	return (error);
}

int
soconnect(so, nam)
	register struct socket *so;
	struct sockaddr *nam;

{
	int s;
	int error;
	struct proc *p = current_proc();
	struct kextcb *kp;

	if (so->so_options & SO_ACCEPTCONN)
		return (EOPNOTSUPP);
	s = splnet();
	/*
	 * If protocol is connection-based, can only connect once.
	 * Otherwise, if connected, try to disconnect first.
	 * This allows user to disconnect by connecting to, e.g.,
	 * a null address.
	 */
	if (so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING) &&
	    ((so->so_proto->pr_flags & PR_CONNREQUIRED) ||
	    (error = sodisconnect(so))))
		error = EISCONN;
	else {
                /*
                 * Run connect filter before calling protocol:
                 *  - non-blocking connect returns before completion;
                 *  - allows filters to modify address.
                 */
                kp = sotokextcb(so);
                while (kp) {
                        if (kp->e_soif && kp->e_soif->sf_soconnect) {
                                error = (*kp->e_soif->sf_soconnect)(so, nam, kp);
                                if (error) {
                                        if (error == EJUSTRETURN) {
                                                error = 0;       
                                        }
                                        splx(s);
                                        return(error);       
                                }
                        }
                        kp = kp->e_next;
                }
		error = (*so->so_proto->pr_usrreqs->pru_connect)(so, nam, p);
	}
	splx(s);
	return (error);
}

int
soconnect2(so1, so2)
	register struct socket *so1;
	struct socket *so2;
{
	int s = splnet();
	int error;
	struct kextcb *kp;

	error = (*so1->so_proto->pr_usrreqs->pru_connect2)(so1, so2);
	if (error == 0) {
		kp = sotokextcb(so1);
		while (kp) {
			if (kp->e_soif && kp->e_soif->sf_soconnect2) {
				error = (*kp->e_soif->sf_soconnect2)(so1, so2, kp);
				if (error) {
					if (error == EJUSTRETURN) {
						return 0;
						break;
					}
					splx(s);
					return(error);
				}
			}
			kp = kp->e_next;
		}
	}
	splx(s);
	return (error);
}

int
sodisconnect(so)
	register struct socket *so;
{
	int s = splnet();
	int error;
	struct kextcb *kp;

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
		kp = sotokextcb(so);
		while (kp) {
			if (kp->e_soif && kp->e_soif->sf_sodisconnect) {
				error = (*kp->e_soif->sf_sodisconnect)(so, kp);
				if (error) {
					if (error == EJUSTRETURN) {
						error = 0;
						break;
					}
					splx(s);
					return(error);
				}
			}
			kp = kp->e_next;
		}
	}

bad:
	splx(s);
	return (error);
}

#define	SBLOCKWAIT(f)	(((f) & MSG_DONTWAIT) ? M_DONTWAIT : M_WAIT)
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
	int clen = 0, error, s, dontroute, mlen, sendflags;
	int atomic = sosendallatonce(so) || top;
	struct proc *p = current_proc();
	struct kextcb *kp;

	if (uio)
		resid = uio->uio_resid;
	else
		resid = top->m_pkthdr.len;

	KERNEL_DEBUG((DBG_FNC_SOSEND | DBG_FUNC_START),
		     so,
		     resid,
		     so->so_snd.sb_cc,
		     so->so_snd.sb_lowat,
		     so->so_snd.sb_hiwat);

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
	if (resid < 0 || so->so_type == SOCK_STREAM && (flags & MSG_EOR)) {
		error = EINVAL;
		goto out;
	}

	dontroute =
	    (flags & MSG_DONTROUTE) && (so->so_options & SO_DONTROUTE) == 0 &&
	    (so->so_proto->pr_flags & PR_ATOMIC);
	if (p)
		p->p_stats->p_ru.ru_msgsnd++;
	if (control)
		clen = control->m_len;
#define	snderr(errno)	{ error = errno; splx(s); goto release; }

restart:
	error = sblock(&so->so_snd, SBLOCKWAIT(flags));
	if (error)
		goto out;
	do {
		s = splnet();
		if (so->so_state & SS_CANTSENDMORE)
			snderr(EPIPE);
		if (so->so_error) {
			error = so->so_error;
			so->so_error = 0;
			splx(s);
			goto release;
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
					snderr(ENOTCONN);
			} else if (addr == 0 && !(flags&MSG_HOLD))
			    snderr(so->so_proto->pr_flags & PR_CONNREQUIRED ?
				   ENOTCONN : EDESTADDRREQ);
		}
		space = sbspace(&so->so_snd);
		if (flags & MSG_OOB)
			space += 1024;
		if ((atomic && resid > so->so_snd.sb_hiwat) ||
		    clen > so->so_snd.sb_hiwat)
			snderr(EMSGSIZE);
		if (space < resid + clen && uio &&
		    (atomic || space < so->so_snd.sb_lowat || space < clen)) {
			if (so->so_state & SS_NBIO)
				snderr(EWOULDBLOCK);
			sbunlock(&so->so_snd);
			error = sbwait(&so->so_snd);
			splx(s);
			if (error)
				goto out;
			goto restart;
		}
		splx(s);
		mp = &top;
		space -= clen;

		do {
		    if (uio == NULL) {
			/*
			 * Data is prepackaged in "top".
			 */
			resid = 0;
			if (flags & MSG_EOR)
				top->m_flags |= M_EOR;
		    } else {
		        boolean_t 	dropped_funnel = FALSE;
			int             chainlength;
			int             bytes_to_copy;

			bytes_to_copy = min(resid, space);

			if (sosendminchain > 0) {
			    if (bytes_to_copy >= sosendminchain) {
			        dropped_funnel = TRUE;
			        (void)thread_funnel_set(network_flock, FALSE);
			    }
			    chainlength = 0;
			} else
			    chainlength = sosendmaxchain;

			do {

			if (bytes_to_copy >= MINCLSIZE) {
			  /*
			   * try to maintain a local cache of mbuf clusters needed to complete this write
			   * the list is further limited to the number that are currently needed to fill the socket
			   * this mechanism allows a large number of mbufs/clusters to be grabbed under a single 
			   * mbuf lock... if we can't get any clusters, than fall back to trying for mbufs
			   * if we fail early (or miscalcluate the number needed) make sure to release any clusters
			   * we haven't yet consumed.
			   */
			  if ((m = freelist) == NULL) {
			        int num_needed;
				int hdrs_needed = 0;
				
				if (top == 0)
				    hdrs_needed = 1;
				num_needed = bytes_to_copy / MCLBYTES;

				if ((bytes_to_copy - (num_needed * MCLBYTES)) >= MINCLSIZE)
				    num_needed++;

			        if ((freelist = m_getpackets(num_needed, hdrs_needed, M_WAIT)) == NULL)
				    goto getpackets_failed;
				m = freelist;
			    }
			    freelist = m->m_next;
			    m->m_next = NULL;

			    mlen = MCLBYTES;
			    len = min(mlen, bytes_to_copy);
			} else {
getpackets_failed:
			    if (top == 0) {
				MGETHDR(m, M_WAIT, MT_DATA);
				mlen = MHLEN;
				m->m_pkthdr.len = 0;
				m->m_pkthdr.rcvif = (struct ifnet *)0;
			    } else {
				MGET(m, M_WAIT, MT_DATA);
				mlen = MLEN;
			    }
			    len = min(mlen, bytes_to_copy);
			    /*
			     * For datagram protocols, leave room
			     * for protocol headers in first mbuf.
			     */
			    if (atomic && top == 0 && len < mlen)
			        MH_ALIGN(m, len);
			}
			chainlength += len;
			
			space -= len;

			error = uiomove(mtod(m, caddr_t), (int)len, uio);

			resid = uio->uio_resid;
			
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

		    if (dropped_funnel == TRUE)
			(void)thread_funnel_set(network_flock, TRUE);
		    if (error)
			goto release;
		    }
            
		    if (flags & (MSG_HOLD|MSG_SEND))
		    {	/* Enqueue for later, go away if HOLD */
			register struct mbuf *mb1;
			if (so->so_temp && (flags & MSG_FLUSH))
			{	m_freem(so->so_temp);
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
			if (flags&MSG_HOLD)
			{	top = NULL;
				goto release;
			}
			top = so->so_temp;
		    }
		    if (dontroute)
			    so->so_options |= SO_DONTROUTE;
		    s = splnet();				/* XXX */
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
		    kp = sotokextcb(so);
		    while (kp)
		    {	if (kp->e_soif && kp->e_soif->sf_sosend) {
					error = (*kp->e_soif->sf_sosend)(so, &addr,
								 &uio, &top,
								 &control,
								 &sendflags,
								 kp);
				if (error) {
					splx(s);
					if (error == EJUSTRETURN) {
						sbunlock(&so->so_snd);
					
					        if (freelist)
						        m_freem_list(freelist);     
						return(0);
					}
					goto release;
				}
			}
			kp = kp->e_next;
		    }

		    error = (*so->so_proto->pr_usrreqs->pru_send)(so,
			sendflags, top, addr, control, p);
		    splx(s);
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
	sbunlock(&so->so_snd);
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
	register struct mbuf *m, **mp;
	register struct mbuf *free_list, *ml;
	register int flags, len, error, s, offset;
	struct protosw *pr = so->so_proto;
	struct mbuf *nextrecord;
	int moff, type = 0;
	int orig_resid = uio->uio_resid;
	struct kextcb *kp;
	
	KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_START,
		     so,
		     uio->uio_resid,
		     so->so_rcv.sb_cc,
		     so->so_rcv.sb_lowat,
		     so->so_rcv.sb_hiwat);

	kp = sotokextcb(so);
	while (kp) {
		if (kp->e_soif && kp->e_soif->sf_soreceive) {
			error = (*kp->e_soif->sf_soreceive)(so, psa, &uio,
							    mp0, controlp,
							    flagsp, kp);
			if (error)
				return((error == EJUSTRETURN) ? 0 : error);
		}
		kp = kp->e_next;
	}

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
		if (m == NULL)
			return (ENOBUFS);
		error = (*pr->pr_usrreqs->pru_rcvoob)(so, m, flags & MSG_PEEK);
		if (error)
			goto bad;
		do {
			error = uiomove(mtod(m, caddr_t),
			    (int) min(uio->uio_resid, m->m_len), uio);
			m = m_free(m);
		} while (uio->uio_resid && error == 0 && m);
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
		KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, error,0,0,0,0);
#endif
		return (error);
	}
nooob:
	if (mp)
		*mp = (struct mbuf *)0;
	if (so->so_state & SS_ISCONFIRMING && uio->uio_resid)
		(*pr->pr_usrreqs->pru_rcvd)(so, 0);

restart:
	error = sblock(&so->so_rcv, SBLOCKWAIT(flags));
	if (error) {
		KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, error,0,0,0,0);
		return (error);
	}
	s = splnet();

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
	    so->so_rcv.sb_cc < uio->uio_resid) &&
	    (so->so_rcv.sb_cc < so->so_rcv.sb_lowat ||
	    ((flags & MSG_WAITALL) && uio->uio_resid <= so->so_rcv.sb_hiwat)) &&
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
		if (uio->uio_resid == 0)
			goto release;
		if ((so->so_state & SS_NBIO) || (flags & MSG_DONTWAIT)) {
			error = EWOULDBLOCK;
			goto release;
		}
		sbunlock(&so->so_rcv);
		if (socket_debug)
		    printf("Waiting for socket data\n");
		error = sbwait(&so->so_rcv);
		if (socket_debug)
		    printf("SORECEIVE - sbwait returned %d\n", error);
		splx(s);
		if (error) {
		    KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, error,0,0,0,0);
		    return (error);
		}
		goto restart;
	}
dontblock:
#ifndef __APPLE__
	if (uio->uio_procp)
		uio->uio_procp->p_stats->p_ru.ru_msgrcv++;
#endif
	nextrecord = m->m_nextpkt;
	if ((pr->pr_flags & PR_ADDR) && m->m_type == MT_SONAME) {
		KASSERT(m->m_type == MT_SONAME, ("receive 1a"));
		orig_resid = 0;
		if (psa)
			*psa = dup_sockaddr(mtod(m, struct sockaddr *),
					    mp0 == 0);
		if (flags & MSG_PEEK) {
			m = m->m_next;
		} else {
			sbfree(&so->so_rcv, m);
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
				    SCM_RIGHTS)
				   error = (*pr->pr_domain->dom_externalize)(m);
				*controlp = m;
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

	free_list = m;
	ml = (struct mbuf *)0;

	while (m && uio->uio_resid > 0 && error == 0) {
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
		len = uio->uio_resid;
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
			splx(s);
			error = uiomove(mtod(m, caddr_t) + moff, (int)len, uio);
			s = splnet();
			if (error)
				goto release;
		} else
			uio->uio_resid -= len;
		if (len == m->m_len - moff) {
			if (m->m_flags & M_EOR)
				flags |= MSG_EOR;
			if (flags & MSG_PEEK) {
				m = m->m_next;
				moff = 0;
			} else {
				nextrecord = m->m_nextpkt;
				sbfree(&so->so_rcv, m);
				if (mp) {
					*mp = m;
					mp = &m->m_next;
					so->so_rcv.sb_mb = m = m->m_next;
					*mp = (struct mbuf *)0;
				} else {
				        m->m_nextpkt = 0;
				        if (ml != 0) 
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
			  	    postevent(so, 0, EV_OOB);
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
		 * If the MSG_WAITALL flag is set (for non-atomic socket),
		 * we must not quit until "uio->uio_resid == 0" or an error
		 * termination.  If a signal/timeout occurs, return
		 * with a short count but without error.
		 * Keep sockbuf locked against other readers.
		 */
		while (flags & MSG_WAITALL && m == 0 && uio->uio_resid > 0 &&
		    !sosendallatonce(so) && !nextrecord) {
			if (so->so_error || so->so_state & SS_CANTRCVMORE)
				break;

			if (ml) {
				m_freem_list(free_list);
			}
			error = sbwait(&so->so_rcv);
			if (error) {
				sbunlock(&so->so_rcv);
				splx(s);
				KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END, 0,0,0,0,0);
				return (0);
			}
			m = so->so_rcv.sb_mb;
			if (m) {
				nextrecord = m->m_nextpkt;
				free_list = m;
			}
			ml = (struct mbuf *)0;
		}
	}
	if (ml) {
	        m_freem_list(free_list);
	}

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
#endif
	if (orig_resid == uio->uio_resid && orig_resid &&
	    (flags & MSG_EOR) == 0 && (so->so_state & SS_CANTRCVMORE) == 0) {
		sbunlock(&so->so_rcv);
		splx(s);
		goto restart;
	}

	if (flagsp)
		*flagsp |= flags;
release:
	sbunlock(&so->so_rcv);
	splx(s);

	KERNEL_DEBUG(DBG_FNC_SORECEIVE | DBG_FUNC_END,
		     so,
		     uio->uio_resid,
		     so->so_rcv.sb_cc,
		     0,
		     error);

	return (error);
}

int
soshutdown(so, how)
	register struct socket *so;
	register int how;
{
	register struct protosw *pr = so->so_proto;
	struct kextcb *kp;
	int ret;


	KERNEL_DEBUG(DBG_FNC_SOSHUTDOWN | DBG_FUNC_START, 0,0,0,0,0);
	kp = sotokextcb(so);
	while (kp) {
		if (kp->e_soif && kp->e_soif->sf_soshutdown) {
			ret = (*kp->e_soif->sf_soshutdown)(so, how, kp);
			if (ret)
				return((ret == EJUSTRETURN) ? 0 : ret);
		}
		kp = kp->e_next;
	}

	if (how != SHUT_WR) {
		sorflush(so);
		postevent(so, 0, EV_RCLOSED);
	}
	if (how != SHUT_RD) {
	    ret = ((*pr->pr_usrreqs->pru_shutdown)(so));
	    postevent(so, 0, EV_WCLOSED);
	    KERNEL_DEBUG(DBG_FNC_SOSHUTDOWN | DBG_FUNC_END, 0,0,0,0,0);
	    return(ret);
	}

	KERNEL_DEBUG(DBG_FNC_SOSHUTDOWN | DBG_FUNC_END, 0,0,0,0,0);
	return (0);
}

void
sorflush(so)
	register struct socket *so;
{
	register struct sockbuf *sb = &so->so_rcv;
	register struct protosw *pr = so->so_proto;
	register int s, error;
	struct sockbuf asb;
	struct kextcb *kp;

	kp = sotokextcb(so);
	while (kp) {
		if (kp->e_soif && kp->e_soif->sf_sorflush) {
			if ((*kp->e_soif->sf_sorflush)(so, kp))
				return;
		}
		kp = kp->e_next;
	}

	sb->sb_flags |= SB_NOINTR;
	(void) sblock(sb, M_WAIT);
	s = splimp();
	socantrcvmore(so);
	sbunlock(sb);
#ifdef __APPLE__
	selthreadclear(&sb->sb_sel);
#endif
	asb = *sb;
	bzero((caddr_t)sb, sizeof (*sb));
#ifndef __APPLE__
	if (asb.sb_flags & SB_KNOTE) {
		sb->sb_sel.si_note = asb.sb_sel.si_note;
		sb->sb_flags = SB_KNOTE;
	}
#endif
	splx(s);
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

	bcopy(sopt->sopt_val, buf, valsize);
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
	struct kextcb *kp;

	if (sopt->sopt_dir != SOPT_SET) {
		sopt->sopt_dir = SOPT_SET;
	}

	kp = sotokextcb(so);
	while (kp) {
		if (kp->e_soif && kp->e_soif->sf_socontrol) {
			error = (*kp->e_soif->sf_socontrol)(so, sopt, kp);
			if (error)
				return((error == EJUSTRETURN) ? 0 : error);
		}
		kp = kp->e_next;
	}

	error = 0;
	if (sopt->sopt_level != SOL_SOCKET) {
		if (so->so_proto && so->so_proto->pr_ctloutput)
			return ((*so->so_proto->pr_ctloutput)
				  (so, sopt));
		error = ENOPROTOOPT;
	} else {
		switch (sopt->sopt_name) {
		case SO_LINGER:
			error = sooptcopyin(sopt, &l, sizeof l, sizeof l);
			if (error)
				goto bad;

			so->so_linger = l.l_linger;
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

			/* assert(hz > 0); */
			if (tv.tv_sec < 0 || tv.tv_sec > SHRT_MAX / hz ||
			    tv.tv_usec < 0 || tv.tv_usec >= 1000000) {
				error = EDOM;
				goto bad;
			}
			/* assert(tick > 0); */
			/* assert(ULONG_MAX - SHRT_MAX >= 1000000); */
			{
			long tmp = (u_long)(tv.tv_sec * hz) + tv.tv_usec / tick;
			if (tmp > SHRT_MAX) {
				error = EDOM;
				goto bad;
			}
			val = tmp;
			}

			switch (sopt->sopt_name) {
			case SO_SNDTIMEO:
				so->so_snd.sb_timeo = val;
				break;
			case SO_RCVTIMEO:
				so->so_rcv.sb_timeo = val;
				break;
			}
			break;

		case SO_NKE:
		{
			struct so_nke nke;
			struct NFDescriptor *nf1, *nf2 = NULL;

			error = sooptcopyin(sopt, &nke,
								sizeof nke, sizeof nke);
			if (error)
			  goto bad;

			error = nke_insert(so, &nke);
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
	if (sopt->sopt_val != 0) {
		if (sopt->sopt_p != 0)
			error = copyout(buf, sopt->sopt_val, valsize);
		else
			bcopy(buf, sopt->sopt_val, valsize);
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
	struct mbuf  *m;
	struct kextcb *kp;

        if (sopt->sopt_dir != SOPT_GET) {
                sopt->sopt_dir = SOPT_GET;
        }

	kp = sotokextcb(so);
	while (kp) {
		if (kp->e_soif && kp->e_soif->sf_socontrol) {
			error = (*kp->e_soif->sf_socontrol)(so, sopt, kp);
			if (error)
				return((error == EJUSTRETURN) ? 0 : error);
		}
		kp = kp->e_next;
	}

	error = 0;
	if (sopt->sopt_level != SOL_SOCKET) {
		if (so->so_proto && so->so_proto->pr_ctloutput) {
			return ((*so->so_proto->pr_ctloutput)
				  (so, sopt));
		} else
			return (ENOPROTOOPT);
	} else {
		switch (sopt->sopt_name) {
		case SO_LINGER:
			l.l_onoff = so->so_options & SO_LINGER;
			l.l_linger = so->so_linger;
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
#if 0
				kprintf("SKT CC: %d\n", so->so_rcv.sb_cc);
#endif
				while (m1) {
					if (m1->m_type == MT_DATA)
						pkt_total += m1->m_len;
#if 0
					kprintf("CNT: %d/%d\n", m1->m_len, pkt_total);
#endif
					m1 = m1->m_next;
				}
				optval = pkt_total;
			} else
				optval = so->so_rcv.sb_cc;
#if 0
			kprintf("RTN: %d\n", optval);
#endif
			goto integer;
		}
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
			optval = (sopt->sopt_name == SO_SNDTIMEO ?
				  so->so_snd.sb_timeo : so->so_rcv.sb_timeo);

			tv.tv_sec = optval / hz;
			tv.tv_usec = (optval % hz) * tick;
			error = sooptcopyout(sopt, &tv, sizeof tv);
			break;			

                case SO_NOSIGPIPE:
                        optval = (so->so_flags & SOF_NOSIGPIPE);
                        goto integer;

		default:
			error = ENOPROTOOPT;
			break;
		}
		return (error);
	}
}

#ifdef __APPLE__
/*
 * Network filter support
 */
/* Run the list of filters, creating extension control blocks */
sfilter_init(register struct socket *so)
{	struct kextcb *kp, **kpp;
	struct protosw *prp;
	struct NFDescriptor *nfp;

	prp = so->so_proto;
	nfp = prp->pr_sfilter.tqh_first; /* non-null */
	kpp = &so->so_ext;
	kp = NULL;
	while (nfp)
	{	MALLOC(kp, struct kextcb *, sizeof(*kp),
			    M_TEMP, M_WAITOK);
		if (kp == NULL)
			return(ENOBUFS); /* so_free will clean up */
		*kpp = kp;
		kpp = &kp->e_next;
		kp->e_next = NULL;
		kp->e_fcb = NULL;
		kp->e_nfd = nfp;
		kp->e_soif = nfp->nf_soif;
		kp->e_sout = nfp->nf_soutil;
		/*
		 * Ignore return value for create
		 * Everyone gets a chance at startup
		 */
		if (kp->e_soif && kp->e_soif->sf_socreate)
			(*kp->e_soif->sf_socreate)(so, prp, kp);
		nfp = nfp->nf_next.tqe_next;
	}
	return(0);
}

/*
 * Run the list of filters, freeing extension control blocks
 * Assumes the soif/soutil blocks have been handled.
 */
sfilter_term(struct socket *so)
{	struct kextcb *kp, *kp1;

	kp = so->so_ext;
	while (kp)
	{	kp1 = kp->e_next;
		/*
		 * Ignore return code on termination; everyone must
		 *  get terminated.
		 */
		if (kp->e_soif && kp->e_soif->sf_sofree)
			kp->e_soif->sf_sofree(so, kp);
		FREE(kp, M_TEMP);
		kp = kp1;
	}
	return(0);
}
#endif __APPLE__

/* XXX; prepare mbuf for (__FreeBSD__ < 3) routines. */
int
soopt_getm(struct sockopt *sopt, struct mbuf **mp)
{
	struct mbuf *m, *m_prev;
	int sopt_size = sopt->sopt_valsize;

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

	if (sopt->sopt_val == NULL)
		return 0;
	while (m != NULL && sopt->sopt_valsize >= m->m_len) {
		if (sopt->sopt_p != NULL) {
			int error;

			error = copyin(sopt->sopt_val, mtod(m, char *),
				       m->m_len);
			if (error != 0) {
				m_freem(m0);
				return(error);
			}
		} else
			bcopy(sopt->sopt_val, mtod(m, char *), m->m_len);
		sopt->sopt_valsize -= m->m_len;
		(caddr_t)sopt->sopt_val += m->m_len;
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

	if (sopt->sopt_val == NULL)
		return 0;
	while (m != NULL && sopt->sopt_valsize >= m->m_len) {
		if (sopt->sopt_p != NULL) {
			int error;

			error = copyout(mtod(m, char *), sopt->sopt_val,
				       m->m_len);
			if (error != 0) {
				m_freem(m0);
				return(error);
			}
		} else
			bcopy(mtod(m, char *), sopt->sopt_val, m->m_len);
	       sopt->sopt_valsize -= m->m_len;
	       (caddr_t)sopt->sopt_val += m->m_len;
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
	struct kextcb *kp;

	kp = sotokextcb(so);
	while (kp) {
		if (kp->e_soif && kp->e_soif->sf_sohasoutofband) {
			if ((*kp->e_soif->sf_sohasoutofband)(so, kp))
				return;
		}
		kp = kp->e_next;
	}
	if (so->so_pgid < 0)
		gsignal(-so->so_pgid, SIGURG);
	else if (so->so_pgid > 0 && (p = pfind(so->so_pgid)) != 0)
		psignal(p, SIGURG);
	selwakeup(&so->so_rcv.sb_sel);
}

int
sopoll(struct socket *so, int events, struct ucred *cred, void * wql)
{
	struct proc *p = current_proc();
	int revents = 0;
	int s = splnet();

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

	splx(s);
	return (revents);
}
