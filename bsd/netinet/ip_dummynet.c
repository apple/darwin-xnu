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
 * Copyright (c) 1998 Luigi Rizzo
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 * Obviously, it would be nice if you gave credit where credit is due
 * but requiring it would be too onerous.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 *
 */

/*
 * This module implements IP dummynet, a bandwidth limiter/delay emulator
 * used in conjunction with the ipfw package.
 *
 * Changes:
 *
 * 980821: changed conventions in the queueing logic
 *	packets passed from dummynet to ip_in/out are prepended with
 *	a vestigial mbuf type MT_DUMMYNET which contains a pointer
 *	to the matching rule.
 *	ip_input/output will extract the parameters, free the vestigial mbuf,
 *	and do the processing.
 *     
 * 980519:	fixed behaviour when deleting rules.
 * 980518:	added splimp()/splx() to protect against races
 * 980513:	initial release
 */

/* include files marked with XXX are probably not needed */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/queue.h>			/* XXX */
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_dummynet.h>
#include <netinet/ip_var.h>

#if BRIDGE
#include <netinet/if_ether.h> /* for struct arpcom */
#include <net/bridge.h>
#endif

static struct dn_pipe *all_pipes = NULL ;	/* list of all pipes */

static int dn_debug = 0 ;			/* verbose */
static int dn_calls = 0 ;			/* number of calls */
static int dn_idle = 1;
#ifdef SYSCTL_NODE
SYSCTL_NODE(_net_inet_ip, OID_AUTO, dummynet, CTLFLAG_RW, 0, "Dummynet");
SYSCTL_INT(_net_inet_ip_dummynet, OID_AUTO, debug, CTLFLAG_RW, &dn_debug, 0, "");
SYSCTL_INT(_net_inet_ip_dummynet, OID_AUTO, calls, CTLFLAG_RD, &dn_calls, 0, "");
SYSCTL_INT(_net_inet_ip_dummynet, OID_AUTO, idle, CTLFLAG_RD, &dn_idle, 0, "");
#endif

static int ip_dn_ctl(struct sockopt *sopt);

static void rt_unref(struct rtentry *);
static void dummynet(void *);
static void dn_restart(void);
static void dn_move(struct dn_pipe *pipe, int immediate);
static void dummynet_flush(void);

/*
 * the following is needed when deleting a pipe, because rules can
 * hold references to the pipe.
 */
extern LIST_HEAD (ip_fw_head, ip_fw_chain) ip_fw_chain;

/*
 * invoked to reschedule the periodic task if necessary.
 * Should only be called when dn_idle = 1 ;
 */
static void
dn_restart()
{
    struct dn_pipe *pipe;

    if (!dn_idle)
	return;
	
    for (pipe = all_pipes ; pipe ; pipe = pipe->next ) {
	/* if there any pipe that needs work, restart */
	if (pipe->r.head || pipe->p.head || pipe->numbytes < 0 ) {
	    dn_idle = 0;
	    timeout(dummynet, NULL, 1);
	    return ;
	}
    }
}

static void
rt_unref(struct rtentry *rt)
{
    if (rt == NULL)
	return ;
    if (rt->rt_refcnt <= 0)
	printf("-- warning, refcnt now %d, decreasing\n", rt->rt_refcnt);
    RTFREE(rt);
}

/*
 * move packets from R-queue to P-queue
 */
static void
dn_move(struct dn_pipe *pipe, int immediate)
{
    struct dn_pkt *pkt;
 
    /*
     * consistency check, should catch new pipes which are
     * not initialized properly.
     */
    if ( pipe->p.head == NULL &&
		pipe->ticks_from_last_insert != pipe->delay) {
	printf("Warning, empty pipe and delay %d (should be %d)\n",
		pipe->ticks_from_last_insert, pipe->delay);
	pipe->ticks_from_last_insert = pipe->delay;
    }
    /* this ought to go in dn_dequeue() */
    if (!immediate && pipe->ticks_from_last_insert < pipe->delay)
	pipe->ticks_from_last_insert++;
    if ( pkt = pipe->r.head ) {
	/*
	 * Move at most numbytes bytes from src and move to dst.
	 * delay is set to ticks_from_last_insert, which
	 * is reset after the first insertion;
	 */
	while ( pkt ) {
	    struct ip *ip=mtod(pkt->dn_m, struct ip *);

	    /*
	     * queue limitation: pass packets down if the len is
	     * such that the pkt would go out before the next tick.
	     */
	    if (pipe->bandwidth) {
		if (pipe->numbytes < ip->ip_len)
		    break;
		pipe->numbytes -= ip->ip_len;
	    }
	    pipe->r_len--; /* elements in queue */
	    pipe->r_len_bytes -= ip->ip_len ;

	    /*
	     * to add delay jitter, must act here. A lower value
	     * (bounded to 0) means lower delay.
	     */
	    pkt->delay = pipe->ticks_from_last_insert;
	    pipe->ticks_from_last_insert = 0;
	    /* compensate the decrement done next in dn_dequeue */
	    if (!immediate && pkt->delay >0 && pipe->p.head==NULL)
		pkt->delay++;
	    if (pipe->p.head == NULL)
		pipe->p.head = pkt;
	    else
		(struct dn_pkt *)pipe->p.tail->dn_next = pkt;
	    pipe->p.tail = pkt;
	    pkt = (struct dn_pkt *)pkt->dn_next;
	    pipe->p.tail->dn_next = NULL;
	}
	pipe->r.head = pkt;
 
	/*** XXX just a sanity check */
	if ( ( pkt == NULL && pipe->r_len != 0) ||
	     ( pkt != NULL && pipe->r_len == 0) )
	    printf("-- Warning, pipe head %p len %d\n",
		    (void *)pkt, pipe->r_len);
    }
 
    /*
     * deliver packets downstream after the delay in the P-queue.
     */

    if (pipe->p.head == NULL)
	return;
    if (!immediate)
	pipe->p.head->delay--;
    while ( (pkt = pipe->p.head) && pkt->delay < 1) {
	/*
	 * first unlink, then call procedures since ip_input()
	 * can result in a call to ip_output cnd viceversa,
	 * thus causing nested calls
	 */
	pipe->p.head = (struct dn_pkt *) pkt->dn_next ;

	/*
	 * the trick to avoid flow-id settings here is to prepend a
	 * vestigial mbuf to the packet, with the following values:
	 * m_type = MT_DUMMYNET
	 * m_next = the actual mbuf to be processed by ip_input/output
	 * m_data = the matching rule
	 * The vestigial element is the same memory area used by
	 * the dn_pkt, and IS FREED IN ip_input/ip_output. IT IS
	 * NOT A REAL MBUF, just a block of memory acquired with malloc().
	 */
	switch (pkt->dn_dir) {
	case DN_TO_IP_OUT: {
	    struct rtentry *tmp_rt = pkt->ro.ro_rt ;

	    (void)ip_output((struct mbuf *)pkt, (struct mbuf *)pkt->ifp,
			&(pkt->ro), pkt->dn_hlen, NULL);
	    rt_unref (tmp_rt) ;
	    }
	    break ;
	case DN_TO_IP_IN :
	    ip_input((struct mbuf *)pkt) ;
	    break ;
#if BRIDGE
	case DN_TO_BDG_FWD :
	    bdg_forward((struct mbuf **)&pkt, pkt->ifp);
	    break ;
#endif
	default:
	    printf("dummynet: bad switch %d!\n", pkt->dn_dir);
	    m_freem(pkt->dn_m);
	    FREE(pkt, M_IPFW);
	    break ;
	}
    }
}
/*
 * this is the periodic task that moves packets between the R-
 * and the P- queue
 */
/*ARGSUSED*/
void
dummynet(void * __unused unused)
{
    struct dn_pipe *p ;
    int s ;
    boolean_t 	funnel_state;

    funnel_state = thread_funnel_set(network_flock, TRUE);
    dn_calls++ ;
    for (p = all_pipes ; p ; p = p->next ) {
	/*
	 * Increment the amount of data that can be sent. However,
	 * don't do that if the channel is idle
	 * (r.head == NULL && numbytes >= bandwidth).
	 * This bug fix is from tim shepard (shep@bbn.com)
	 */
        s = splimp();
	if (p->r.head != NULL || p->numbytes < p->bandwidth )
		p->numbytes += p->bandwidth ;
	dn_move(p, 0); /* is it really 0 (also below) ? */
	splx(s);
    }
 
    /*
     * finally, if some queue has data, restart the timer.
     */
    dn_idle = 1;
    dn_restart();
    (void) thread_funnel_set(network_flock, funnel_state);

}

/*
 * dummynet hook for packets.
 * input and output use the same code, so i use bit 16 in the pipe
 * number to chose the direction: 1 for output packets, 0 for input.
 * for input, only m is significant. For output, also the others.
 */
int
dummynet_io(int pipe_nr, int dir,
	struct mbuf *m, struct ifnet *ifp, struct route *ro, int hlen,
	struct ip_fw_chain *rule)
{
    struct dn_pkt *pkt;
    struct dn_pipe *pipe;
    struct ip *ip=mtod(m, struct ip *);

    int s=splimp();

    pipe_nr &= 0xffff ;
    /*
     * locate pipe. First time is expensive, next have direct access.
     */

    if ( (pipe = rule->rule->pipe_ptr) == NULL ) {
	for (pipe=all_pipes; pipe && pipe->pipe_nr !=pipe_nr; pipe=pipe->next)
	    ;
	if (pipe == NULL) {
	    splx(s);
	    if (dn_debug)
		printf("warning, pkt for no pipe %d\n", pipe_nr);
	    m_freem(m);
	    return 0 ;
	} else
	    rule->rule->pipe_ptr = pipe ;
    }
 
    /*
     * should i drop ?
     * This section implements random packet drop.
     */
    if ( (pipe->plr && random() < pipe->plr) ||
         (pipe->queue_size && pipe->r_len >= pipe->queue_size) ||
         (pipe->queue_size_bytes &&
	    ip->ip_len + pipe->r_len_bytes > pipe->queue_size_bytes) ||
		(pkt = (struct dn_pkt *) _MALLOC(sizeof (*pkt),
			M_IPFW, M_WAITOK) ) == NULL ) {
	splx(s);
	if (dn_debug)
	    printf("-- dummynet: drop from pipe %d, have %d pks, %d bytes\n",
		pipe_nr,  pipe->r_len, pipe->r_len_bytes);
	pipe->r_drops++ ;
	m_freem(m);
	return 0 ; /* XXX error */
    }
    bzero(pkt, sizeof(*pkt) );
    /* build and enqueue packet */
    pkt->hdr.mh_type = MT_DUMMYNET ;
    (struct ip_fw_chain *)pkt->hdr.mh_data = rule ;
    pkt->dn_next = NULL;
    pkt->dn_m = m;
    pkt->dn_dir = dir ;
    pkt->delay = 0;

    pkt->ifp = ifp;
    if (dir == DN_TO_IP_OUT) {
	pkt->ro = *ro; /* XXX copied! */
	if (ro->ro_rt)
	    ro->ro_rt->rt_refcnt++ ; /* XXX */
    }
    pkt->dn_hlen = hlen;
    if (pipe->r.head == NULL)
	pipe->r.head = pkt;
    else
	(struct dn_pkt *)pipe->r.tail->dn_next = pkt;
    pipe->r.tail = pkt;
    pipe->r_len++;
    pipe->r_len_bytes += ip->ip_len ;

    /* 
     * here we could implement RED if we like to
     */

    if (pipe->r.head == pkt) {       /* process immediately */
        dn_move(pipe, 1);
    }
    splx(s);
    if (dn_idle)
	dn_restart();
    return 0;
}

/*
 * dispose all packets queued on a pipe
 */
static void
purge_pipe(struct dn_pipe *pipe)
{
    struct dn_pkt *pkt, *n ;
    struct rtentry *tmp_rt ;

    for (pkt = pipe->r.head ; pkt ; ) {
	rt_unref (tmp_rt = pkt->ro.ro_rt ) ;
	m_freem(pkt->dn_m);
	n = pkt ;
	pkt = (struct dn_pkt *)pkt->dn_next ;
	FREE(n, M_IPFW) ;
    }
    for (pkt = pipe->p.head ; pkt ; ) {
	rt_unref (tmp_rt = pkt->ro.ro_rt ) ;
	m_freem(pkt->dn_m);
	n = pkt ;
	pkt = (struct dn_pkt *)pkt->dn_next ;
	FREE(n, M_IPFW) ;
    }
}

/*
 * delete all pipes returning memory
 */
static void
dummynet_flush()
{
    struct dn_pipe *q, *p = all_pipes ;
    int s = splnet() ;

    all_pipes = NULL ;
    splx(s) ;
    /*
     * purge all queued pkts and delete all pipes
     */
    for ( ; p ; ) {
	purge_pipe(p);
	q = p ;
	p = p->next ;	
	FREE(q, M_IPFW);
    }
}

extern struct ip_fw_chain *ip_fw_default_rule ;
/*
 * when a firewall rule is deleted, scan all pipes and remove the flow-id
 * from packets matching this rule.
 */
void
dn_rule_delete(void *r)
{
    struct dn_pipe *p ;
    int matches = 0 ;

    for ( p = all_pipes ; p ; p = p->next ) {
	struct dn_pkt *x ;
	for (x = p->r.head ; x ; x = (struct dn_pkt *)x->dn_next )
	    if (x->hdr.mh_data == r) {
		matches++ ;
		x->hdr.mh_data = (void *)ip_fw_default_rule ;
	    }
	for (x = p->p.head ; x ; x = (struct dn_pkt *)x->dn_next )
	    if (x->hdr.mh_data == r) {
		matches++ ;
		x->hdr.mh_data = (void *)ip_fw_default_rule ;
	    }
    }
    printf("dn_rule_delete, r %p, default %p%s, %d matches\n",
	    (void *)r, (void *)ip_fw_default_rule,
	    r == ip_fw_default_rule ? "  AARGH!":"",  matches);
}

/*
 * handler for the various dummynet socket options
 * (get, flush, config, del)
 */
static int
ip_dn_ctl(struct sockopt *sopt)
{
    int error = 0 ;
    size_t size ;
    char *buf, *bp ;
    struct dn_pipe *p, tmp_pipe ;

    struct dn_pipe *x, *a, *b ;

    /* Disallow sets in really-really secure mode. */
    if (sopt->sopt_dir == SOPT_SET && securelevel >= 3)
	return (EPERM);

    switch (sopt->sopt_name) {
    default :
	panic("ip_dn_ctl -- unknown option");

    case IP_DUMMYNET_GET :
	for (p = all_pipes, size = 0 ; p ; p = p->next )
	    size += sizeof( *p ) ;
	buf = _MALLOC(size, M_TEMP, M_WAITOK);
	if (buf == 0) {
	    error = ENOBUFS ;
	    break ;
	}
	for (p = all_pipes, bp = buf ; p ; p = p->next ) {
	    struct dn_pipe *q = (struct dn_pipe *)bp ;

	    bcopy(p, bp, sizeof( *p ) );
		/*
		 * return bw and delay in bits/s and ms, respectively
		 */
		q->bandwidth *= (8*hz) ;
		q->delay = (q->delay * 1000) / hz ;
	    bp += sizeof( *p ) ;
	}
	error = sooptcopyout(sopt, buf, size);
	FREE(buf, M_TEMP);
	break ;
    case IP_DUMMYNET_FLUSH :
	    dummynet_flush() ;
	break ;
    case IP_DUMMYNET_CONFIGURE :
	p = &tmp_pipe ;
	error = sooptcopyin(sopt, p, sizeof *p, sizeof *p);
	if (error)
	    break ;
	    /*
	     * The config program passes parameters as follows:
	     * bandwidth = bits/second (0 = no limits);
	     *    must be translated in bytes/tick.
	     * delay = ms
	     *    must be translated in ticks.
	     * queue_size = slots (0 = no limit)
	     * queue_size_bytes = bytes (0 = no limit)
	     *	  only one can be set, must be bound-checked
	     */
	    if ( p->bandwidth > 0 ) {
		p->bandwidth = p->bandwidth / 8 / hz ;
		if (p->bandwidth == 0)	/* too little does not make sense! */
			p->bandwidth = 10 ;
	    }
	    p->delay = ( p->delay * hz ) / 1000 ;
	    if (p->queue_size == 0 && p->queue_size_bytes == 0)
		p->queue_size = 100 ;
	    if (p->queue_size != 0 )	/* buffers are prevailing */
		p->queue_size_bytes = 0 ;
	    if (p->queue_size > 100)
		p->queue_size = 100 ;
	    if (p->queue_size_bytes > 1024*1024)
		p->queue_size_bytes = 1024*1024 ;
#if 0
	    printf("ip_dn: config pipe %d %d bit/s %d ms %d bufs\n",
		p->pipe_nr,
		p->bandwidth * 8 * hz ,
		p->delay * 1000 / hz , p->queue_size);
#endif
	    for (a = NULL , b = all_pipes ; b && b->pipe_nr < p->pipe_nr ;
		 a = b , b = b->next) ;
	    if (b && b->pipe_nr == p->pipe_nr) {
		/* XXX should spl and flush old pipe... */
		b->bandwidth = p->bandwidth ;
		b->delay = p->delay ;
		b->ticks_from_last_insert = p->delay ;
		b->queue_size = p->queue_size ;
		b->queue_size_bytes = p->queue_size_bytes ;
		b->plr = p->plr ;
	    } else {
		int s ;
		x = _MALLOC(sizeof(struct dn_pipe), M_IPFW, M_NOWAIT) ;
		if (x == NULL) {
		    printf("ip_dummynet.c: sorry no memory\n");
		error = ENOSPC ;
		break ;
		}
		bzero(x, sizeof(*x) );
		x->bandwidth = p->bandwidth ;
		x->delay = p->delay ;
		x->ticks_from_last_insert = p->delay ;
		x->pipe_nr = p->pipe_nr ;
		x->queue_size = p->queue_size ;
		x->queue_size_bytes = p->queue_size_bytes ;
		x->plr = p->plr ;

		s = splnet() ;
		x->next = b ;
		if (a == NULL)
		    all_pipes = x ;
		else
		    a->next = x ;
		splx(s);
	    }
	break ;

    case IP_DUMMYNET_DEL :
	p = &tmp_pipe ;
	error = sooptcopyin(sopt, p, sizeof *p, sizeof *p);
	if (error)
	    break ;

	    for (a = NULL , b = all_pipes ; b && b->pipe_nr < p->pipe_nr ;
		 a = b , b = b->next) ;
	    if (b && b->pipe_nr == p->pipe_nr) {	/* found pipe */
		int s = splnet() ;
		struct ip_fw_chain *chain = ip_fw_chain.lh_first;

		if (a == NULL)
		    all_pipes = b->next ;
		else
		    a->next = b->next ;
		/*
		 * remove references to this pipe from the ip_fw rules.
		 */
		for (; chain; chain = chain->chain.le_next) {
		    register struct ip_fw *const f = chain->rule;
		    if (f->pipe_ptr == b)
			f->pipe_ptr = NULL ;
		}
		splx(s);
		purge_pipe(b);	/* remove pkts from here */
		FREE(b, M_IPFW);
	    }
	break ;
	}
    return error ;
}

void
ip_dn_init(void)
{
    printf("DUMMYNET initialized (980901) -- size dn_pkt %d\n",
	sizeof(struct dn_pkt));
    all_pipes = NULL ;
    ip_dn_ctl_ptr = ip_dn_ctl;
}

#if DUMMYNET_MODULE

#include <sys/exec.h>
#include <sys/sysent.h>
#include <sys/lkm.h>

MOD_MISC(dummynet);

static ip_dn_ctl_t *old_dn_ctl_ptr ;

static int
dummynet_load(struct lkm_table *lkmtp, int cmd)
{
	int s=splnet();
	old_dn_ctl_ptr = ip_dn_ctl_ptr;
	ip_dn_init();
	splx(s);
	return 0;
}

static int
dummynet_unload(struct lkm_table *lkmtp, int cmd)
{
	int s=splnet();
	ip_dn_ctl_ptr =  old_dn_ctl_ptr;
	splx(s);
	dummynet_flush();
	printf("DUMMYNET unloaded\n");
	return 0;
}

int
dummynet_mod(struct lkm_table *lkmtp, int cmd, int ver)
{
    DISPATCH(lkmtp, cmd, ver, dummynet_load, dummynet_unload, lkm_nullcmd);
}
#endif
