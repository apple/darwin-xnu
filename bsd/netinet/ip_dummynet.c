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
 * Copyright (c) 1998-2001 Luigi Rizzo, Universita` di Pisa
 * Portions Copyright (c) 2000 Akamba Corp.
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/netinet/ip_dummynet.c,v 1.24.2.11 2001/02/09 23:18:08 luigi Exp $
 */

#define DEB(x)
#define DDB(x)	x

/*
 * This module implements IP dummynet, a bandwidth limiter/delay emulator
 * used in conjunction with the ipfw package.
 * Description of the data structures used is in ip_dummynet.h
 * Here you mainly find the following blocks of code:
 *  + variable declarations;
 *  + heap management functions;
 *  + scheduler and dummynet functions;
 *  + configuration and initialization.
 *
 * NOTA BENE: critical sections are protected by splimp()/splx()
 *    pairs. One would think that splnet() is enough as for most of
 *    the netinet code, but it is not so because when used with
 *    bridging, dummynet is invoked at splimp().
 *
 * Most important Changes:
 *
 * 010124: Fixed WF2Q behaviour
 * 010122: Fixed spl protection.
 * 000601: WF2Q support
 * 000106: large rewrite, use heaps to handle very many pipes.
 * 980513:	initial release
 *
 * include files marked with XXX are probably not needed
 */

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

/*
 * We keep a private variable for the simulation time, but we could
 * probably use an existing one ("softticks" in sys/kern/kern_timer.c)
 */
static dn_key curr_time = 0 ; /* current simulation time */

static int dn_hash_size = 64 ;	/* default hash size */

/* statistics on number of queue searches and search steps */
static int searches, search_steps ;
static int pipe_expire = 1 ;   /* expire queue if empty */
static int dn_max_ratio = 16 ; /* max queues/buckets ratio */

static int red_lookup_depth = 256;	/* RED - default lookup table depth */
static int red_avg_pkt_size = 512;      /* RED - default medium packet size */
static int red_max_pkt_size = 1500;     /* RED - default max packet size */

/*
 * Three heaps contain queues and pipes that the scheduler handles:
 *
 * ready_heap contains all dn_flow_queue related to fixed-rate pipes.
 *
 * wfq_ready_heap contains the pipes associated with WF2Q flows
 *
 * extract_heap contains pipes associated with delay lines.
 *
 */
static struct dn_heap ready_heap, extract_heap, wfq_ready_heap ;

static int heap_init(struct dn_heap *h, int size) ;
static int heap_insert (struct dn_heap *h, dn_key key1, void *p);
static void heap_extract(struct dn_heap *h, void *obj);

static void transmit_event(struct dn_pipe *pipe);
static void ready_event(struct dn_flow_queue *q);

static struct dn_pipe *all_pipes = NULL ;	/* list of all pipes */
static struct dn_flow_set *all_flow_sets = NULL ;/* list of all flow_sets */

#if SYSCTL_NODE
SYSCTL_NODE(_net_inet_ip, OID_AUTO, dummynet,
		CTLFLAG_RW, 0, "Dummynet");
SYSCTL_INT(_net_inet_ip_dummynet, OID_AUTO, hash_size,
	    CTLFLAG_RW, &dn_hash_size, 0, "Default hash table size");
SYSCTL_INT(_net_inet_ip_dummynet, OID_AUTO, curr_time,
	    CTLFLAG_RD, &curr_time, 0, "Current tick");
SYSCTL_INT(_net_inet_ip_dummynet, OID_AUTO, ready_heap,
	    CTLFLAG_RD, &ready_heap.size, 0, "Size of ready heap");
SYSCTL_INT(_net_inet_ip_dummynet, OID_AUTO, extract_heap,
	    CTLFLAG_RD, &extract_heap.size, 0, "Size of extract heap");
SYSCTL_INT(_net_inet_ip_dummynet, OID_AUTO, searches,
	    CTLFLAG_RD, &searches, 0, "Number of queue searches");
SYSCTL_INT(_net_inet_ip_dummynet, OID_AUTO, search_steps,
	    CTLFLAG_RD, &search_steps, 0, "Number of queue search steps");
SYSCTL_INT(_net_inet_ip_dummynet, OID_AUTO, expire,
	    CTLFLAG_RW, &pipe_expire, 0, "Expire queue if empty");
SYSCTL_INT(_net_inet_ip_dummynet, OID_AUTO, max_chain_len,
	    CTLFLAG_RW, &dn_max_ratio, 0, 
	"Max ratio between dynamic queues and buckets");
SYSCTL_INT(_net_inet_ip_dummynet, OID_AUTO, red_lookup_depth,
	CTLFLAG_RD, &red_lookup_depth, 0, "Depth of RED lookup table");
SYSCTL_INT(_net_inet_ip_dummynet, OID_AUTO, red_avg_pkt_size,
	CTLFLAG_RD, &red_avg_pkt_size, 0, "RED Medium packet size");
SYSCTL_INT(_net_inet_ip_dummynet, OID_AUTO, red_max_pkt_size,
	CTLFLAG_RD, &red_max_pkt_size, 0, "RED Max packet size");
#endif

static int config_pipe(struct dn_pipe *p);
static int ip_dn_ctl(struct sockopt *sopt);

static void rt_unref(struct rtentry *);
static void dummynet(void *);
static void dummynet_flush(void);
void dummynet_drain(void);
int if_tx_rdy(struct ifnet *ifp);

/*
 * ip_fw_chain is used when deleting a pipe, because ipfw rules can
 * hold references to the pipe.
 */
extern LIST_HEAD (ip_fw_head, ip_fw_chain) ip_fw_chain_head;

static void
rt_unref(struct rtentry *rt)
{
    if (rt == NULL)
	return ;
    if (rt->rt_refcnt <= 0)
	printf("-- warning, refcnt now %ld, decreasing\n", rt->rt_refcnt);
    rtfree(rt);
}

/*
 * Heap management functions.
 *
 * In the heap, first node is element 0. Children of i are 2i+1 and 2i+2.
 * Some macros help finding parent/children so we can optimize them.
 *
 * heap_init() is called to expand the heap when needed.
 * Increment size in blocks of 16 entries.
 * XXX failure to allocate a new element is a pretty bad failure
 * as we basically stall a whole queue forever!!
 * Returns 1 on error, 0 on success
 */
#define HEAP_FATHER(x) ( ( (x) - 1 ) / 2 )
#define HEAP_LEFT(x) ( 2*(x) + 1 )
#define HEAP_IS_LEFT(x) ( (x) & 1 )
#define HEAP_RIGHT(x) ( 2*(x) + 2 )
#define	HEAP_SWAP(a, b, buffer) { buffer = a ; a = b ; b = buffer ; }
#define HEAP_INCREMENT	15

static int
heap_init(struct dn_heap *h, int new_size)
{       
    struct dn_heap_entry *p;

    if (h->size >= new_size ) {
	printf("heap_init, Bogus call, have %d want %d\n",
		h->size, new_size);
	return 0 ;
    }   
    new_size = (new_size + HEAP_INCREMENT ) & ~HEAP_INCREMENT ;
    p = _MALLOC(new_size * sizeof(*p), M_IPFW, M_DONTWAIT );
    if (p == NULL) {
	printf(" heap_init, resize %d failed\n", new_size );
	return 1 ; /* error */
    }
    if (h->size > 0) {
	bcopy(h->p, p, h->size * sizeof(*p) );
	FREE(h->p, M_IPFW);
    }
    h->p = p ;
    h->size = new_size ;
    return 0 ;
}

/*
 * Insert element in heap. Normally, p != NULL, we insert p in
 * a new position and bubble up. If p == NULL, then the element is
 * already in place, and key is the position where to start the
 * bubble-up.
 * Returns 1 on failure (cannot allocate new heap entry)
 *
 * If offset > 0 the position (index, int) of the element in the heap is
 * also stored in the element itself at the given offset in bytes.
 */
#define SET_OFFSET(heap, node) \
    if (heap->offset > 0) \
	    *((int *)((char *)(heap->p[node].object) + heap->offset)) = node ;
/*
 * RESET_OFFSET is used for sanity checks. It sets offset to an invalid value.
 */
#define RESET_OFFSET(heap, node) \
    if (heap->offset > 0) \
	    *((int *)((char *)(heap->p[node].object) + heap->offset)) = -1 ;
static int
heap_insert(struct dn_heap *h, dn_key key1, void *p)
{   
    int son = h->elements ;

    if (p == NULL)	/* data already there, set starting point */
	son = key1 ;
    else {		/* insert new element at the end, possibly resize */
	son = h->elements ;
	if (son == h->size) /* need resize... */
	    if (heap_init(h, h->elements+1) )
		return 1 ; /* failure... */
	h->p[son].object = p ;
	h->p[son].key = key1 ;
	h->elements++ ;
    }
    while (son > 0) {				/* bubble up */
	int father = HEAP_FATHER(son) ;
	struct dn_heap_entry tmp  ;

	if (DN_KEY_LT( h->p[father].key, h->p[son].key ) )
	    break ; /* found right position */ 
	/* son smaller than father, swap and repeat */
	HEAP_SWAP(h->p[son], h->p[father], tmp) ;
	SET_OFFSET(h, son);
	son = father ;
    }
    SET_OFFSET(h, son);
    return 0 ;
}

/*
 * remove top element from heap, or obj if obj != NULL
 */
static void
heap_extract(struct dn_heap *h, void *obj)
{  
    int child, father, max = h->elements - 1 ;

    if (max < 0) {
	printf("warning, extract from empty heap 0x%p\n", h);
	return ;
    }
    father = 0 ; /* default: move up smallest child */
    if (obj != NULL) { /* extract specific element, index is at offset */
	if (h->offset <= 0)
	    panic("*** heap_extract from middle not supported on this heap!!!\n");
	father = *((int *)((char *)obj + h->offset)) ;
	if (father < 0 || father >= h->elements) {
	    printf("dummynet: heap_extract, father %d out of bound 0..%d\n",
		father, h->elements);
	    panic("heap_extract");
	}
    }
    RESET_OFFSET(h, father);
    child = HEAP_LEFT(father) ;		/* left child */
    while (child <= max) {		/* valid entry */
	if (child != max && DN_KEY_LT(h->p[child+1].key, h->p[child].key) )
	    child = child+1 ;		/* take right child, otherwise left */
	h->p[father] = h->p[child] ;
	SET_OFFSET(h, father);
	father = child ;
	child = HEAP_LEFT(child) ;   /* left child for next loop */
    }   
    h->elements-- ;
    if (father != max) {
	/*
	 * Fill hole with last entry and bubble up, reusing the insert code
	 */
	h->p[father] = h->p[max] ;
	heap_insert(h, father, NULL); /* this one cannot fail */
    }
}           

#if 0
/*
 * change object position and update references
 * XXX this one is never used!
 */
static void
heap_move(struct dn_heap *h, dn_key new_key, void *object)
{
    int temp;
    int i ;
    int max = h->elements-1 ;
    struct dn_heap_entry buf ;

    if (h->offset <= 0)
	panic("cannot move items on this heap");

    i = *((int *)((char *)object + h->offset));
    if (DN_KEY_LT(new_key, h->p[i].key) ) { /* must move up */
	h->p[i].key = new_key ;
	for (; i>0 && DN_KEY_LT(new_key, h->p[(temp = HEAP_FATHER(i))].key) ;
		 i = temp ) { /* bubble up */
	    HEAP_SWAP(h->p[i], h->p[temp], buf) ;
	    SET_OFFSET(h, i);
	}
    } else {		/* must move down */
	h->p[i].key = new_key ;
	while ( (temp = HEAP_LEFT(i)) <= max ) { /* found left child */
	    if ((temp != max) && DN_KEY_GT(h->p[temp].key, h->p[temp+1].key))
		temp++ ; /* select child with min key */
	    if (DN_KEY_GT(new_key, h->p[temp].key)) { /* go down */
		HEAP_SWAP(h->p[i], h->p[temp], buf) ;
		SET_OFFSET(h, i);
	    } else
		break ;
	    i = temp ;
	}
    }
    SET_OFFSET(h, i);
}
#endif /* heap_move, unused */

/*
 * heapify() will reorganize data inside an array to maintain the
 * heap property. It is needed when we delete a bunch of entries.
 */
static void
heapify(struct dn_heap *h)
{
    int i ;

    for (i = 0 ; i < h->elements ; i++ )
	heap_insert(h, i , NULL) ;
}

/*
 * cleanup the heap and free data structure
 */
static void
heap_free(struct dn_heap *h)
{
    if (h->size >0 )
	FREE(h->p, M_IPFW);
    bzero(h, sizeof(*h) );
}

/*
 * --- end of heap management functions ---
 */

/*
 * Scheduler functions:
 *
 * transmit_event() is called when the delay-line needs to enter
 * the scheduler, either because of existing pkts getting ready,
 * or new packets entering the queue. The event handled is the delivery
 * time of the packet.
 *
 * ready_event() does something similar with fixed-rate queues, and the
 * event handled is the finish time of the head pkt.
 *
 * wfq_ready_event() does something similar with WF2Q queues, and the
 * event handled is the start time of the head pkt.
 *
 * In all cases, we make sure that the data structures are consistent
 * before passing pkts out, because this might trigger recursive
 * invocations of the procedures.
 */
static void
transmit_event(struct dn_pipe *pipe)
{
    struct dn_pkt *pkt ;

    while ( (pkt = pipe->head) && DN_KEY_LEQ(pkt->output_time, curr_time) ) {
	/*
	 * first unlink, then call procedures, since ip_input() can invoke
	 * ip_output() and viceversa, thus causing nested calls
	 */
	pipe->head = DN_NEXT(pkt) ;

	/*
	 * The actual mbuf is preceded by a struct dn_pkt, resembling an mbuf
	 * (NOT A REAL one, just a small block of malloc'ed memory) with
	 *     m_type = MT_DUMMYNET
	 *     m_next = actual mbuf to be processed by ip_input/output
	 *     m_data = the matching rule
	 * and some other fields.
	 * The block IS FREED HERE because it contains parameters passed
	 * to the called routine.
	 */
	switch (pkt->dn_dir) {
	case DN_TO_IP_OUT:
	    (void)ip_output((struct mbuf *)pkt, NULL, NULL, 0, NULL);
	    rt_unref (pkt->ro.ro_rt) ;
	    break ;

	case DN_TO_IP_IN :
	    ip_input((struct mbuf *)pkt) ;
	    break ;

#if BRIDGE
	case DN_TO_BDG_FWD : {
	    struct mbuf *m = (struct mbuf *)pkt ;
	    struct ether_header *eh;

	    if (pkt->dn_m->m_len < ETHER_HDR_LEN
	      && (pkt->dn_m = m_pullup(pkt->dn_m, ETHER_HDR_LEN)) == NULL) {
		printf("dummynet/bridge: pullup fail, dropping pkt\n");
		break;
	    }
	    /*
	     * same as ether_input, make eh be a pointer into the mbuf
	     */
	    eh = mtod(pkt->dn_m, struct ether_header *);
	    m_adj(pkt->dn_m, ETHER_HDR_LEN);
	    /*
	     * bdg_forward() wants a pointer to the pseudo-mbuf-header, but
	     * on return it will supply the pointer to the actual packet
	     * (originally pkt->dn_m, but could be something else now) if
	     * it has not consumed it.
	     */
	    m = bdg_forward(m, eh, pkt->ifp);
	    if (m)
		m_freem(m);
	    }
	    break ;
#endif

	default:
	    printf("dummynet: bad switch %d!\n", pkt->dn_dir);
	    m_freem(pkt->dn_m);
	    break ;
	}
	FREE(pkt, M_IPFW);
    }
    /* if there are leftover packets, put into the heap for next event */
    if ( (pkt = pipe->head) )
         heap_insert(&extract_heap, pkt->output_time, pipe ) ;
    /* XXX should check errors on heap_insert, by draining the
     * whole pipe p and hoping in the future we are more successful
     */
}

/*
 * the following macro computes how many ticks we have to wait
 * before being able to transmit a packet. The credit is taken from
 * either a pipe (WF2Q) or a flow_queue (per-flow queueing)
 */
#define SET_TICKS(pkt, q, p)	\
    (pkt->dn_m->m_pkthdr.len*8*hz - (q)->numbytes + p->bandwidth - 1 ) / \
	    p->bandwidth ;

/*
 * extract pkt from queue, compute output time (could be now)
 * and put into delay line (p_queue)
 */
static void
move_pkt(struct dn_pkt *pkt, struct dn_flow_queue *q,
	struct dn_pipe *p, int len)
{
    q->head = DN_NEXT(pkt) ;
    q->len-- ;
    q->len_bytes -= len ;

    pkt->output_time = curr_time + p->delay ;

    if (p->head == NULL)
	p->head = pkt;
    else
	DN_NEXT(p->tail) = pkt;
    p->tail = pkt;
    DN_NEXT(p->tail) = NULL;
}

/*
 * ready_event() is invoked every time the queue must enter the
 * scheduler, either because the first packet arrives, or because
 * a previously scheduled event fired.
 * On invokation, drain as many pkts as possible (could be 0) and then
 * if there are leftover packets reinsert the pkt in the scheduler.
 */
static void
ready_event(struct dn_flow_queue *q)
{
    struct dn_pkt *pkt;
    struct dn_pipe *p = q->fs->pipe ;
    int p_was_empty ;

    if (p == NULL) {
	printf("ready_event- pipe is gone\n");
	return ;
    }
    p_was_empty = (p->head == NULL) ;

    /*
     * schedule fixed-rate queues linked to this pipe:
     * Account for the bw accumulated since last scheduling, then
     * drain as many pkts as allowed by q->numbytes and move to
     * the delay line (in p) computing output time.
     * bandwidth==0 (no limit) means we can drain the whole queue,
     * setting len_scaled = 0 does the job.
     */
    q->numbytes += ( curr_time - q->sched_time ) * p->bandwidth;
    while ( (pkt = q->head) != NULL ) {
	int len = pkt->dn_m->m_pkthdr.len;
	int len_scaled = p->bandwidth ? len*8*hz : 0 ;
	if (len_scaled > q->numbytes )
	    break ;
	q->numbytes -= len_scaled ;
	move_pkt(pkt, q, p, len);
    }
    /*
     * If we have more packets queued, schedule next ready event
     * (can only occur when bandwidth != 0, otherwise we would have
     * flushed the whole queue in the previous loop).
     * To this purpose we record the current time and compute how many
     * ticks to go for the finish time of the packet.
     */
    if ( (pkt = q->head) != NULL ) { /* this implies bandwidth != 0 */
	dn_key t = SET_TICKS(pkt, q, p); /* ticks i have to wait */
	q->sched_time = curr_time ;
	heap_insert(&ready_heap, curr_time + t, (void *)q );
	/* XXX should check errors on heap_insert, and drain the whole
	 * queue on error hoping next time we are luckier.
	 */
    } else	/* RED needs to know when the queue becomes empty */
	q->q_time = curr_time;
    /*
     * If the delay line was empty call transmit_event(p) now.
     * Otherwise, the scheduler will take care of it.
     */
    if (p_was_empty)
	transmit_event(p);
}

/*
 * Called when we can transmit packets on WF2Q queues. Take pkts out of
 * the queues at their start time, and enqueue into the delay line.
 * Packets are drained until p->numbytes < 0. As long as
 * len_scaled >= p->numbytes, the packet goes into the delay line
 * with a deadline p->delay. For the last packet, if p->numbytes<0,
 * there is an additional delay.
 */
static void
ready_event_wfq(struct dn_pipe *p)
{
    int p_was_empty = (p->head == NULL) ;
    struct dn_heap *sch = &(p->scheduler_heap);
    struct dn_heap *neh = &(p->not_eligible_heap) ;

    if (p->if_name[0] == 0) /* tx clock is simulated */
	p->numbytes += ( curr_time - p->sched_time ) * p->bandwidth;
    else { /* tx clock is for real, the ifq must be empty or this is a NOP */
	if (p->ifp && p->ifp->if_snd.ifq_head != NULL)
	    return ;
	else {
	    DEB(printf("pipe %d ready from %s --\n",
		p->pipe_nr, p->if_name);)
	}
    }

    /*
     * While we have backlogged traffic AND credit, we need to do
     * something on the queue.
     */
    while ( p->numbytes >=0 && (sch->elements>0 || neh->elements >0) ) {
	if (sch->elements > 0) { /* have some eligible pkts to send out */
	    struct dn_flow_queue *q = sch->p[0].object ;
	    struct dn_pkt *pkt = q->head;  
	    struct dn_flow_set *fs = q->fs;   
	    u_int64_t len = pkt->dn_m->m_pkthdr.len;
	    int len_scaled = p->bandwidth ? len*8*hz : 0 ;

	    heap_extract(sch, NULL); /* remove queue from heap */
	    p->numbytes -= len_scaled ;
	    move_pkt(pkt, q, p, len);

	    p->V += (len<<MY_M) / p->sum ; /* update V */
	    q->S = q->F ; /* update start time */
	    if (q->len == 0) { /* Flow not backlogged any more */
		fs->backlogged-- ;
		heap_insert(&(p->idle_heap), q->F, q);
	    } else { /* still backlogged */
		/*
		 * update F and position in backlogged queue, then
		 * put flow in not_eligible_heap (we will fix this later).
		 */
		len = (q->head)->dn_m->m_pkthdr.len;
		q->F += (len<<MY_M)/(u_int64_t) fs->weight ;
		if (DN_KEY_LEQ(q->S, p->V))
		    heap_insert(neh, q->S, q);
		else
		    heap_insert(sch, q->F, q);
	    }
	}
	/*
	 * now compute V = max(V, min(S_i)). Remember that all elements in sch
	 * have by definition S_i <= V so if sch is not empty, V is surely
	 * the max and we must not update it. Conversely, if sch is empty
	 * we only need to look at neh.
	 */
	if (sch->elements == 0 && neh->elements > 0)
	    p->V = MAX64 ( p->V, neh->p[0].key );
	/* move from neh to sch any packets that have become eligible */
	while (neh->elements > 0 && DN_KEY_LEQ(neh->p[0].key, p->V) ) {
	    struct dn_flow_queue *q = neh->p[0].object ;
	    heap_extract(neh, NULL);
	    heap_insert(sch, q->F, q);
	}

	if (p->if_name[0] != '\0') {/* tx clock is from a real thing */
	    p->numbytes = -1 ; /* mark not ready for I/O */
	    break ;
	}
    }
    if (sch->elements == 0 && neh->elements == 0 && p->numbytes >= 0
	    && p->idle_heap.elements > 0) {
	/*
	 * no traffic and no events scheduled. We can get rid of idle-heap.
	 */
	int i ;

	for (i = 0 ; i < p->idle_heap.elements ; i++) {
	    struct dn_flow_queue *q = p->idle_heap.p[i].object ;

	    q->F = 0 ;
	    q->S = q->F + 1 ;
	}
	p->sum = 0 ;
	p->V = 0 ;
	p->idle_heap.elements = 0 ;
    }
    /*
     * If we are getting clocks from dummynet (not a real interface) and
     * If we are under credit, schedule the next ready event.
     * Also fix the delivery time of the last packet.
     */
    if (p->if_name[0]==0 && p->numbytes < 0) { /* this implies bandwidth >0 */
	dn_key t=0 ; /* number of ticks i have to wait */

	if (p->bandwidth > 0)
	    t = ( p->bandwidth -1 - p->numbytes) / p->bandwidth ;
	p->tail->output_time += t ;
	p->sched_time = curr_time ;
	heap_insert(&wfq_ready_heap, curr_time + t, (void *)p);
	/* XXX should check errors on heap_insert, and drain the whole
	 * queue on error hoping next time we are luckier.
	 */
    }
    /*
     * If the delay line was empty call transmit_event(p) now.
     * Otherwise, the scheduler will take care of it.
     */
    if (p_was_empty)
	transmit_event(p);
}

/*
 * This is called once per tick, or HZ times per second. It is used to
 * increment the current tick counter and schedule expired events.
 */
static void
dummynet(void * __unused unused)
{
    void *p ; /* generic parameter to handler */
    struct dn_heap *h ;
    int s ;
    struct dn_heap *heaps[3];
    int i;
    struct dn_pipe *pe ;

    heaps[0] = &ready_heap ;		/* fixed-rate queues */
    heaps[1] = &wfq_ready_heap ;	/* wfq queues */
    heaps[2] = &extract_heap ;		/* delay line */
    s = splimp(); /* see note on top, splnet() is not enough */
    curr_time++ ;
    for (i=0; i < 3 ; i++) {
	h = heaps[i];
	while (h->elements > 0 && DN_KEY_LEQ(h->p[0].key, curr_time) ) {
	    DDB(if (h->p[0].key > curr_time)
		printf("-- dummynet: warning, heap %d is %d ticks late\n",
		    i, (int)(curr_time - h->p[0].key));)
	    p = h->p[0].object ; /* store a copy before heap_extract */
	    heap_extract(h, NULL); /* need to extract before processing */
	    if (i == 0)
		ready_event(p) ;
	    else if (i == 1) {
		struct dn_pipe *pipe = p;
		if (pipe->if_name[0] != '\0')
		    printf("*** bad ready_event_wfq for pipe %s\n",
			pipe->if_name);
		else
		    ready_event_wfq(p) ;
	    } else
		transmit_event(p);
	}
    }
    /* sweep pipes trying to expire idle flow_queues */
    for (pe = all_pipes; pe ; pe = pe->next )
	if (pe->idle_heap.elements > 0 &&
		DN_KEY_LT(pe->idle_heap.p[0].key, pe->V) ) {
	    struct dn_flow_queue *q = pe->idle_heap.p[0].object ;

	    heap_extract(&(pe->idle_heap), NULL);
	    q->S = q->F + 1 ; /* mark timestamp as invalid */
	    pe->sum -= q->fs->weight ;
	}
    splx(s);
    timeout(dummynet, NULL, 1);
}
 
/*
 * called by an interface when tx_rdy occurs.
 */
int
if_tx_rdy(struct ifnet *ifp)
{
    struct dn_pipe *p;

    for (p = all_pipes; p ; p = p->next )
	if (p->ifp == ifp)
	    break ;
    if (p == NULL) {
	char buf[32];
	sprintf(buf, "%s%d",ifp->if_name, ifp->if_unit);
	for (p = all_pipes; p ; p = p->next )
	    if (!strcmp(p->if_name, buf) ) {
		p->ifp = ifp ;
		DEB(printf("++ tx rdy from %s (now found)\n", buf);)
		break ;
	    }
    }
    if (p != NULL) {
	DEB(printf("++ tx rdy from %s%d - qlen %d\n", ifp->if_name,
		ifp->if_unit, ifp->if_snd.ifq_len);)
	p->numbytes = 0 ; /* mark ready for I/O */
	ready_event_wfq(p);
    }
    return 0;
}

/*
 * Unconditionally expire empty queues in case of shortage.
 * Returns the number of queues freed.
 */
static int
expire_queues(struct dn_flow_set *fs)
{
    struct dn_flow_queue *q, *prev ;
    int i, initial_elements = fs->rq_elements ;

    if (fs->last_expired == time_second)
	return 0 ;
    fs->last_expired = time_second ;
    for (i = 0 ; i <= fs->rq_size ; i++) /* last one is overflow */
	for (prev=NULL, q = fs->rq[i] ; q != NULL ; )
	    if (q->head != NULL || q->S != q->F+1) {
  		prev = q ;
  	        q = q->next ;
  	    } else { /* entry is idle, expire it */
		struct dn_flow_queue *old_q = q ;

		if (prev != NULL)
		    prev->next = q = q->next ;
		else
		    fs->rq[i] = q = q->next ;
		fs->rq_elements-- ;
		FREE(old_q, M_IPFW);
	    }
    return initial_elements - fs->rq_elements ;
}

/*
 * If room, create a new queue and put at head of slot i;
 * otherwise, create or use the default queue.
 */
static struct dn_flow_queue *
create_queue(struct dn_flow_set *fs, int i)
{
    struct dn_flow_queue *q ;

    if (fs->rq_elements > fs->rq_size * dn_max_ratio &&
	    expire_queues(fs) == 0) {
	/*
	 * No way to get room, use or create overflow queue.
	 */
	i = fs->rq_size ;
	if ( fs->rq[i] != NULL )
	    return fs->rq[i] ;
    }
    q = _MALLOC(sizeof(*q), M_IPFW, M_DONTWAIT) ;
    if (q == NULL) {
	printf("sorry, cannot allocate queue for new flow\n");
	return NULL ;
    }
    bzero(q, sizeof(*q) );     /* needed */
    q->fs = fs ;
    q->hash_slot = i ;
    q->next = fs->rq[i] ;
    q->S = q->F + 1;   /* hack - mark timestamp as invalid */
    fs->rq[i] = q ;
    fs->rq_elements++ ;
    return q ;
}

/*
 * Given a flow_set and a pkt in last_pkt, find a matching queue
 * after appropriate masking. The queue is moved to front
 * so that further searches take less time.
 */
static struct dn_flow_queue *
find_queue(struct dn_flow_set *fs)
{
    int i = 0 ; /* we need i and q for new allocations */
    struct dn_flow_queue *q, *prev;

    if ( !(fs->flags_fs & DN_HAVE_FLOW_MASK) )
	q = fs->rq[0] ;
    else {
	/* first, do the masking */
	last_pkt.dst_ip &= fs->flow_mask.dst_ip ;
	last_pkt.src_ip &= fs->flow_mask.src_ip ;
	last_pkt.dst_port &= fs->flow_mask.dst_port ;
	last_pkt.src_port &= fs->flow_mask.src_port ;
	last_pkt.proto &= fs->flow_mask.proto ;
	last_pkt.flags = 0 ; /* we don't care about this one */
	/* then, hash function */
	i = ( (last_pkt.dst_ip) & 0xffff ) ^
	    ( (last_pkt.dst_ip >> 15) & 0xffff ) ^
	    ( (last_pkt.src_ip << 1) & 0xffff ) ^
	    ( (last_pkt.src_ip >> 16 ) & 0xffff ) ^
	    (last_pkt.dst_port << 1) ^ (last_pkt.src_port) ^
	    (last_pkt.proto );
	i = i % fs->rq_size ;
	/* finally, scan the current list for a match */
	searches++ ;
	for (prev=NULL, q = fs->rq[i] ; q ; ) {
	    search_steps++;
	    if (bcmp(&last_pkt, &(q->id), sizeof(q->id) ) == 0)
		break ; /* found */
	    else if (pipe_expire && q->head == NULL && q->S == q->F+1 ) {
		/* entry is idle and not in any heap, expire it */
		struct dn_flow_queue *old_q = q ;

		if (prev != NULL)
		    prev->next = q = q->next ;
		else
		    fs->rq[i] = q = q->next ;
		fs->rq_elements-- ;
		FREE(old_q, M_IPFW);
		continue ;
	    }
	    prev = q ;
	    q = q->next ;
	}
	if (q && prev != NULL) { /* found and not in front */
	    prev->next = q->next ;
	    q->next = fs->rq[i] ;
	    fs->rq[i] = q ;
	}
    }
    if (q == NULL) { /* no match, need to allocate a new entry */
	q = create_queue(fs, i);
	if (q != NULL)
	q->id = last_pkt ;
    }
    return q ;
}

static int
red_drops(struct dn_flow_set *fs, struct dn_flow_queue *q, int len)
{
    /*
     * RED algorithm
     * 
     * RED calculates the average queue size (avg) using a low-pass filter
     * with an exponential weighted (w_q) moving average:
     * 	avg  <-  (1-w_q) * avg + w_q * q_size
     * where q_size is the queue length (measured in bytes or * packets).
     * 
     * If q_size == 0, we compute the idle time for the link, and set
     *	avg = (1 - w_q)^(idle/s)
     * where s is the time needed for transmitting a medium-sized packet.
     * 
     * Now, if avg < min_th the packet is enqueued.
     * If avg > max_th the packet is dropped. Otherwise, the packet is
     * dropped with probability P function of avg.
     * 
     */

    int64_t p_b = 0;
    /* queue in bytes or packets ? */
    u_int q_size = (fs->flags_fs & DN_QSIZE_IS_BYTES) ? q->len_bytes : q->len;

    DEB(printf("\n%d q: %2u ", (int) curr_time, q_size);)

    /* average queue size estimation */
    if (q_size != 0) {
	/*
	 * queue is not empty, avg <- avg + (q_size - avg) * w_q
	 */
	int diff = SCALE(q_size) - q->avg;
	int64_t v = SCALE_MUL((int64_t) diff, (int64_t) fs->w_q);

	q->avg += (int) v;
    } else {
	/*
	 * queue is empty, find for how long the queue has been
	 * empty and use a lookup table for computing
	 * (1 - * w_q)^(idle_time/s) where s is the time to send a
	 * (small) packet.
	 * XXX check wraps...
	 */
	if (q->avg) {
	    u_int t = (curr_time - q->q_time) / fs->lookup_step;

	    q->avg = (t < fs->lookup_depth) ?
		    SCALE_MUL(q->avg, fs->w_q_lookup[t]) : 0;
	}
    }
    DEB(printf("avg: %u ", SCALE_VAL(q->avg));)

    /* should i drop ? */

    if (q->avg < fs->min_th) {
	q->count = -1;
	return 0; /* accept packet ; */
    }
    if (q->avg >= fs->max_th) { /* average queue >=  max threshold */
	if (fs->flags_fs & DN_IS_GENTLE_RED) {
	    /*
	     * According to Gentle-RED, if avg is greater than max_th the
	     * packet is dropped with a probability
	     *	p_b = c_3 * avg - c_4
	     * where c_3 = (1 - max_p) / max_th, and c_4 = 1 - 2 * max_p
	     */
	    p_b = SCALE_MUL((int64_t) fs->c_3, (int64_t) q->avg) - fs->c_4;
	} else {
	    q->count = -1;
	    printf("- drop");
	    return 1 ;
	}
    } else if (q->avg > fs->min_th) {
	/*
	 * we compute p_b using the linear dropping function p_b = c_1 *
	 * avg - c_2, where c_1 = max_p / (max_th - min_th), and c_2 =
	 * max_p * min_th / (max_th - min_th)
	 */
	p_b = SCALE_MUL((int64_t) fs->c_1, (int64_t) q->avg) - fs->c_2;
    }
    if (fs->flags_fs & DN_QSIZE_IS_BYTES)
	p_b = (p_b * len) / fs->max_pkt_size;
    if (++q->count == 0)
	q->random = random() & 0xffff;
    else {
	/*
	 * q->count counts packets arrived since last drop, so a greater
	 * value of q->count means a greater packet drop probability.
	 */
	if (SCALE_MUL(p_b, SCALE((int64_t) q->count)) > q->random) {
	    q->count = 0;
	    DEB(printf("- red drop");)
	    /* after a drop we calculate a new random value */
	    q->random = random() & 0xffff;
	    return 1;    /* drop */
	}
    }
    /* end of RED algorithm */
    return 0 ; /* accept */
}

static __inline
struct dn_flow_set *
locate_flowset(int pipe_nr, struct ip_fw_chain *rule)
{
    struct dn_flow_set *fs = NULL ;

    if ( (rule->rule->fw_flg & IP_FW_F_COMMAND) == IP_FW_F_QUEUE )
	for (fs=all_flow_sets; fs && fs->fs_nr != pipe_nr; fs=fs->next)
	    ;
    else {
	struct dn_pipe *p1;
	for (p1 = all_pipes; p1 && p1->pipe_nr != pipe_nr; p1 = p1->next)
	    ;
	if (p1 != NULL)
	    fs = &(p1->fs) ;
    }
    if (fs != NULL)
	rule->rule->pipe_ptr = fs ; /* record for the future */
    return fs ;
}

/*
 * dummynet hook for packets. Below 'pipe' is a pipe or a queue
 * depending on whether WF2Q or fixed bw is used.
 */
int
dummynet_io(int pipe_nr, int dir,	/* pipe_nr can also be a fs_nr */
	struct mbuf *m, struct ifnet *ifp, struct route *ro,
	struct sockaddr_in *dst,
	struct ip_fw_chain *rule, int flags)
{
    struct dn_pkt *pkt;
    struct dn_flow_set *fs;
    struct dn_pipe *pipe ;
    u_int64_t len = m->m_pkthdr.len ;
    struct dn_flow_queue *q = NULL ;
    int s ;

    s = splimp();

    pipe_nr &= 0xffff ;

    if ( (fs = rule->rule->pipe_ptr) == NULL ) {
	fs = locate_flowset(pipe_nr, rule);
	if (fs == NULL)
	    goto dropit ;	/* this queue/pipe does not exist! */
    }
    pipe = fs->pipe ;
    if (pipe == NULL) { /* must be a queue, try find a matching pipe */
	for (pipe = all_pipes; pipe && pipe->pipe_nr != fs->parent_nr;
		 pipe = pipe->next)
	    ;
	if (pipe != NULL)
	    fs->pipe = pipe ;
	else {
	    printf("No pipe %d for queue %d, drop pkt\n",
		fs->parent_nr, fs->fs_nr);
	    goto dropit ;
	}
    }
    q = find_queue(fs);
    if ( q == NULL )
	goto dropit ;		/* cannot allocate queue		*/
    /*
     * update statistics, then check reasons to drop pkt
     */
    q->tot_bytes += len ;
    q->tot_pkts++ ;
    if ( fs->plr && random() < fs->plr )
	goto dropit ;		/* random pkt drop			*/
    if ( fs->flags_fs & DN_QSIZE_IS_BYTES) {
    	if (q->len_bytes > fs->qsize)
	    goto dropit ;	/* queue size overflow			*/
    } else {
	if (q->len >= fs->qsize)
	    goto dropit ;	/* queue count overflow			*/
    }
    if ( fs->flags_fs & DN_IS_RED && red_drops(fs, q, len) )
	goto dropit ;

    pkt = (struct dn_pkt *)_MALLOC(sizeof (*pkt), M_IPFW, M_NOWAIT) ;
    if ( pkt == NULL )
	goto dropit ;		/* cannot allocate packet header	*/
    /* ok, i can handle the pkt now... */
    bzero(pkt, sizeof(*pkt) ); /* XXX expensive, see if we can remove it*/
    /* build and enqueue packet + parameters */
    pkt->hdr.mh_type = MT_DUMMYNET ;
    (struct ip_fw_chain *)pkt->hdr.mh_data = rule ;
    DN_NEXT(pkt) = NULL;
    pkt->dn_m = m;
    pkt->dn_dir = dir ;

    pkt->ifp = ifp;
    if (dir == DN_TO_IP_OUT) {
	/*
	 * We need to copy *ro because for ICMP pkts (and maybe others)
	 * the caller passed a pointer into the stack; dst might also be
	 * a pointer into *ro so it needs to be updated.
	 */
	pkt->ro = *ro;
	if (ro->ro_rt)
	    rtref(ro->ro_rt);
	if (dst == (struct sockaddr_in *)&ro->ro_dst) /* dst points into ro */
	    dst = (struct sockaddr_in *)&(pkt->ro.ro_dst) ;

	pkt->dn_dst = dst;
	pkt->flags = flags ;
    }
    if (q->head == NULL)
	q->head = pkt;
    else
	DN_NEXT(q->tail) = pkt;
    q->tail = pkt;
    q->len++;
    q->len_bytes += len ;

    if ( q->head != pkt )	/* flow was not idle, we are done */
	goto done;
    /*
     * If we reach this point the flow was previously idle, so we need
     * to schedule it. This involves different actions for fixed-rate or
     * WF2Q queues.
     */
    if ( (rule->rule->fw_flg & IP_FW_F_COMMAND) == IP_FW_F_PIPE ) {
	/*
	 * Fixed-rate queue: just insert into the ready_heap.
	 */
	dn_key t = 0 ;
	if (pipe->bandwidth) 
	    t = SET_TICKS(pkt, q, pipe);
	q->sched_time = curr_time ;
	if (t == 0)	/* must process it now */
	    ready_event( q );
	else
	    heap_insert(&ready_heap, curr_time + t , q );
    } else {
	/*
	 * WF2Q. First, compute start time S: if the flow was idle (S=F+1)
	 * set S to the virtual time V for the controlling pipe, and update
	 * the sum of weights for the pipe; otherwise, remove flow from
	 * idle_heap and set S to max(F,V).
	 * Second, compute finish time F = S + len/weight.
	 * Third, if pipe was idle, update V=max(S, V).
	 * Fourth, count one more backlogged flow.
	 */
	if (DN_KEY_GT(q->S, q->F)) { /* means timestamps are invalid */
	    q->S = pipe->V ;
	    pipe->sum += fs->weight ; /* add weight of new queue */
	} else {
	    heap_extract(&(pipe->idle_heap), q);
	    q->S = MAX64(q->F, pipe->V ) ;
	}
	q->F = q->S + ( len<<MY_M )/(u_int64_t) fs->weight;

	if (pipe->not_eligible_heap.elements == 0 &&
		pipe->scheduler_heap.elements == 0)
	    pipe->V = MAX64 ( q->S, pipe->V );
	fs->backlogged++ ;
	/*
	 * Look at eligibility. A flow is not eligibile if S>V (when
	 * this happens, it means that there is some other flow already
	 * scheduled for the same pipe, so the scheduler_heap cannot be
	 * empty). If the flow is not eligible we just store it in the
	 * not_eligible_heap. Otherwise, we store in the scheduler_heap
	 * and possibly invoke ready_event_wfq() right now if there is
	 * leftover credit.
	 * Note that for all flows in scheduler_heap (SCH), S_i <= V,
	 * and for all flows in not_eligible_heap (NEH), S_i > V .
	 * So when we need to compute max( V, min(S_i) ) forall i in SCH+NEH,
	 * we only need to look into NEH.
	 */
	if (DN_KEY_GT(q->S, pipe->V) ) { /* not eligible */
	    if (pipe->scheduler_heap.elements == 0)
		printf("++ ouch! not eligible but empty scheduler!\n");
	    heap_insert(&(pipe->not_eligible_heap), q->S, q);
	} else {
	    heap_insert(&(pipe->scheduler_heap), q->F, q);
	    if (pipe->numbytes >= 0) { /* pipe is idle */
		if (pipe->scheduler_heap.elements != 1)
		    printf("*** OUCH! pipe should have been idle!\n");
		DEB(printf("Waking up pipe %d at %d\n",
			pipe->pipe_nr, (int)(q->F >> MY_M)); )
		pipe->sched_time = curr_time ;
		ready_event_wfq(pipe);
	    }
	}
    }
done:
    splx(s);
    return 0;

dropit:
    splx(s);
    if (q)
	q->drops++ ;
    m_freem(m);
    return ENOBUFS ;
}

/*
 * Below, the rt_unref is only needed when (pkt->dn_dir == DN_TO_IP_OUT)
 * Doing this would probably save us the initial bzero of dn_pkt
 */
#define DN_FREE_PKT(pkt)	{		\
	struct dn_pkt *n = pkt ;		\
	rt_unref ( n->ro.ro_rt ) ;		\
	m_freem(n->dn_m);			\
	pkt = DN_NEXT(n) ;			\
	FREE(n, M_IPFW) ;	}

/*
 * Dispose all packets and flow_queues on a flow_set.
 * If all=1, also remove red lookup table and other storage,
 * including the descriptor itself.
 * For the one in dn_pipe MUST also cleanup ready_heap...
 */
static void
purge_flow_set(struct dn_flow_set *fs, int all)
{
    struct dn_pkt *pkt ;
    struct dn_flow_queue *q, *qn ;
    int i ;

    for (i = 0 ; i <= fs->rq_size ; i++ ) {
	for (q = fs->rq[i] ; q ; q = qn ) {
	    for (pkt = q->head ; pkt ; )
		DN_FREE_PKT(pkt) ;
	    qn = q->next ;
	    FREE(q, M_IPFW);
	}
	fs->rq[i] = NULL ;
    }
    fs->rq_elements = 0 ;
    if (all) {
	/* RED - free lookup table */
	if (fs->w_q_lookup)
	    FREE(fs->w_q_lookup, M_IPFW);
	if (fs->rq)
	    FREE(fs->rq, M_IPFW);
	/* if this fs is not part of a pipe, free it */
	if (fs->pipe && fs != &(fs->pipe->fs) )
	    FREE(fs, M_IPFW);
    }
}

/*
 * Dispose all packets queued on a pipe (not a flow_set).
 * Also free all resources associated to a pipe, which is about
 * to be deleted.
 */
static void
purge_pipe(struct dn_pipe *pipe)
{
    struct dn_pkt *pkt ;

    purge_flow_set( &(pipe->fs), 1 );

    for (pkt = pipe->head ; pkt ; )
	DN_FREE_PKT(pkt) ;

    heap_free( &(pipe->scheduler_heap) );
    heap_free( &(pipe->not_eligible_heap) );
    heap_free( &(pipe->idle_heap) );
}

/*
 * Delete all pipes and heaps returning memory. Must also
 * remove references from all ipfw rules to all pipes.
 */
static void
dummynet_flush()
{
    struct dn_pipe *curr_p, *p ;
    struct ip_fw_chain *chain ;
    struct dn_flow_set *fs, *curr_fs;
    int s ;

    s = splimp() ;

    /* remove all references to pipes ...*/
    LIST_FOREACH(chain, &ip_fw_chain_head, next)
	chain->rule->pipe_ptr = NULL ;
    /* prevent future matches... */
    p = all_pipes ;
    all_pipes = NULL ; 
    fs = all_flow_sets ;
    all_flow_sets = NULL ;
    /* and free heaps so we don't have unwanted events */
    heap_free(&ready_heap);
    heap_free(&wfq_ready_heap);
    heap_free(&extract_heap);
    splx(s) ;
    /*
     * Now purge all queued pkts and delete all pipes
     */
    /* scan and purge all flow_sets. */
    for ( ; fs ; ) {
	curr_fs = fs ;
	fs = fs->next ;
	purge_flow_set(curr_fs, 1);
    }
    for ( ; p ; ) {
	purge_pipe(p);
	curr_p = p ;
	p = p->next ;	
	FREE(q, M_IPFW);
    }
}


extern struct ip_fw_chain *ip_fw_default_rule ;
static void
dn_rule_delete_fs(struct dn_flow_set *fs, void *r)
{
    int i ;
    struct dn_flow_queue *q ;
    struct dn_pkt *pkt ;

    for (i = 0 ; i <= fs->rq_size ; i++) /* last one is ovflow */
	for (q = fs->rq[i] ; q ; q = q->next )
	    for (pkt = q->head ; pkt ; pkt = DN_NEXT(pkt) )
		if (pkt->hdr.mh_data == r)
		    pkt->hdr.mh_data = (void *)ip_fw_default_rule ;
}
/*
 * when a firewall rule is deleted, scan all queues and remove the flow-id
 * from packets matching this rule.
 */
void
dn_rule_delete(void *r)
{
    struct dn_pipe *p ;
    struct dn_pkt *pkt ;
    struct dn_flow_set *fs ;

    /*
     * If the rule references a queue (dn_flow_set), then scan
     * the flow set, otherwise scan pipes. Should do either, but doing
     * both does not harm.
     */
    for ( fs = all_flow_sets ; fs ; fs = fs->next )
	dn_rule_delete_fs(fs, r);
    for ( p = all_pipes ; p ; p = p->next ) {
	fs = &(p->fs) ;
	dn_rule_delete_fs(fs, r);
	for (pkt = p->head ; pkt ; pkt = DN_NEXT(pkt) )
	    if (pkt->hdr.mh_data == r)
		pkt->hdr.mh_data = (void *)ip_fw_default_rule ;
    }
}

/*
 * setup RED parameters
 */
static int
config_red(struct dn_flow_set *p, struct dn_flow_set * x) 
{
    int i;

    x->w_q = p->w_q;
    x->min_th = SCALE(p->min_th);
    x->max_th = SCALE(p->max_th);
    x->max_p = p->max_p;

    x->c_1 = p->max_p / (p->max_th - p->min_th);
    x->c_2 = SCALE_MUL(x->c_1, SCALE(p->min_th));
    if (x->flags_fs & DN_IS_GENTLE_RED) {
	x->c_3 = (SCALE(1) - p->max_p) / p->max_th;
	x->c_4 = (SCALE(1) - 2 * p->max_p);
    }

    /* if the lookup table already exist, free and create it again */
    if (x->w_q_lookup)
	FREE(x->w_q_lookup, M_IPFW);
    if (red_lookup_depth == 0) {
	printf("\nnet.inet.ip.dummynet.red_lookup_depth must be > 0");
	FREE(x, M_IPFW);
	return EINVAL;
    }
    x->lookup_depth = red_lookup_depth;
    x->w_q_lookup = (u_int *) _MALLOC(x->lookup_depth * sizeof(int),
	    M_IPFW, M_DONTWAIT);
    if (x->w_q_lookup == NULL) {
	printf("sorry, cannot allocate red lookup table\n");
	FREE(x, M_IPFW);
	return ENOSPC;
    }

    /* fill the lookup table with (1 - w_q)^x */
    x->lookup_step = p->lookup_step ;
    x->lookup_weight = p->lookup_weight ;
    x->w_q_lookup[0] = SCALE(1) - x->w_q;
    for (i = 1; i < x->lookup_depth; i++)
	x->w_q_lookup[i] = SCALE_MUL(x->w_q_lookup[i - 1], x->lookup_weight);
    if (red_avg_pkt_size < 1)
	red_avg_pkt_size = 512 ;
    x->avg_pkt_size = red_avg_pkt_size ;
    if (red_max_pkt_size < 1)
	red_max_pkt_size = 1500 ;
    x->max_pkt_size = red_max_pkt_size ;
    return 0 ;
}

static int
alloc_hash(struct dn_flow_set *x, struct dn_flow_set *pfs)
{
    if (x->flags_fs & DN_HAVE_FLOW_MASK) {     /* allocate some slots */
	int l = pfs->rq_size;

	if (l == 0)
	    l = dn_hash_size;
	if (l < 4)
	    l = 4;
	else if (l > 1024)
	    l = 1024;
	x->rq_size = l;
    } else                  /* one is enough for null mask */
	x->rq_size = 1;
    x->rq = _MALLOC((1 + x->rq_size) * sizeof(struct dn_flow_queue *),
	    M_IPFW, M_DONTWAIT);
    if (x->rq == NULL) {
	printf("sorry, cannot allocate queue\n");
	return ENOSPC;
    }
    bzero(x->rq, (1+x->rq_size) * sizeof(struct dn_flow_queue *));
    x->rq_elements = 0;
    return 0 ;
}

static void
set_fs_parms(struct dn_flow_set *x, struct dn_flow_set *src)
{
    x->flags_fs = src->flags_fs;
    x->qsize = src->qsize;
    x->plr = src->plr;
    x->flow_mask = src->flow_mask;
    if (x->flags_fs & DN_QSIZE_IS_BYTES) {
	if (x->qsize > 1024*1024)
	    x->qsize = 1024*1024 ;
    } else {
	if (x->qsize == 0)
	    x->qsize = 50 ;
	if (x->qsize > 100)
	    x->qsize = 50 ;
    }
    /* configuring RED */
    if ( x->flags_fs & DN_IS_RED )
	config_red(src, x) ;    /* XXX should check errors */
}

/*
 * setup pipe or queue parameters.
 */

static int 
config_pipe(struct dn_pipe *p)
{
    int s ;
    struct dn_flow_set *pfs = &(p->fs);

	/*
	 * The config program passes parameters as follows:
     * bw = bits/second (0 means no limits),
     * delay = ms, must be translated into ticks.
     * qsize = slots/bytes
	 */
	p->delay = ( p->delay * hz ) / 1000 ;
    /* We need either a pipe number or a flow_set number */
    if (p->pipe_nr == 0 && pfs->fs_nr == 0)
	return EINVAL ;
    if (p->pipe_nr != 0 && pfs->fs_nr != 0)
	return EINVAL ;
    if (p->pipe_nr != 0) { /* this is a pipe */
	struct dn_pipe *x, *a, *b;
	/* locate pipe */
	for (a = NULL , b = all_pipes ; b && b->pipe_nr < p->pipe_nr ;
		 a = b , b = b->next) ;

	if (b == NULL || b->pipe_nr != p->pipe_nr) { /* new pipe */
	    x = _MALLOC(sizeof(struct dn_pipe), M_IPFW, M_DONTWAIT) ;
	    if (x == NULL) {
		printf("ip_dummynet.c: no memory for new pipe\n");
		return ENOSPC;
	    }
	    bzero(x, sizeof(struct dn_pipe));
	    x->pipe_nr = p->pipe_nr;
	    x->fs.pipe = x ;
	    /* idle_heap is the only one from which we extract from the middle.
	     */
	    x->idle_heap.size = x->idle_heap.elements = 0 ;
	    x->idle_heap.offset=OFFSET_OF(struct dn_flow_queue, heap_pos);
	} else
	    x = b;

	    x->bandwidth = p->bandwidth ;
	x->numbytes = 0; /* just in case... */
	bcopy(p->if_name, x->if_name, sizeof(p->if_name) );
	x->ifp = NULL ; /* reset interface ptr */
	    x->delay = p->delay ;
	set_fs_parms(&(x->fs), pfs);


	if ( x->fs.rq == NULL ) { /* a new pipe */
	    s = alloc_hash(&(x->fs), pfs) ;
	    if (s) {
		FREE(x, M_IPFW);
		return s ;
	    }
	    s = splimp() ;
	    x->next = b ;
	    if (a == NULL)
		all_pipes = x ;
	    else
		a->next = x ;
	    splx(s);
	}
    } else { /* config queue */
	struct dn_flow_set *x, *a, *b ;

	/* locate flow_set */
	for (a=NULL, b=all_flow_sets ; b && b->fs_nr < pfs->fs_nr ;
		 a = b , b = b->next) ;

	if (b == NULL || b->fs_nr != pfs->fs_nr) { /* new  */
	    if (pfs->parent_nr == 0)	/* need link to a pipe */
		return EINVAL ;
	    x = _MALLOC(sizeof(struct dn_flow_set), M_IPFW, M_DONTWAIT);
	    if (x == NULL) {
		printf("ip_dummynet.c: no memory for new flow_set\n");
		return ENOSPC;
	    }
	    bzero(x, sizeof(struct dn_flow_set));
	    x->fs_nr = pfs->fs_nr;
	    x->parent_nr = pfs->parent_nr;
	    x->weight = pfs->weight ;
	    if (x->weight == 0)
		x->weight = 1 ;
	    else if (x->weight > 100)
		x->weight = 100 ;
	} else {
	    /* Change parent pipe not allowed; must delete and recreate */
	    if (pfs->parent_nr != 0 && b->parent_nr != pfs->parent_nr)
		return EINVAL ;
	    x = b;
	}
	set_fs_parms(x, pfs);

	if ( x->rq == NULL ) { /* a new flow_set */
	    s = alloc_hash(x, pfs) ;
	    if (s) {
		FREE(x, M_IPFW);
		return s ;
	    }
	    s = splimp() ;
	    x->next = b;
	    if (a == NULL)
		all_flow_sets = x;
	    else
		a->next = x;
	    splx(s);
	}
    }
    return 0 ;
}

/*
 * Helper function to remove from a heap queues which are linked to
 * a flow_set about to be deleted.
 */
static void
fs_remove_from_heap(struct dn_heap *h, struct dn_flow_set *fs)
{
    int i = 0, found = 0 ;
    for (; i < h->elements ;)
	if ( ((struct dn_flow_queue *)h->p[i].object)->fs == fs) {
	    h->elements-- ;
	    h->p[i] = h->p[h->elements] ;
	    found++ ;
	} else
	    i++ ;
    if (found)
	heapify(h);
}

/*
 * helper function to remove a pipe from a heap (can be there at most once)
 */
static void
pipe_remove_from_heap(struct dn_heap *h, struct dn_pipe *p)
{
    if (h->elements > 0) {
	int i = 0 ;
	for (i=0; i < h->elements ; i++ ) {
	    if (h->p[i].object == p) { /* found it */
		h->elements-- ;
		h->p[i] = h->p[h->elements] ;
		heapify(h);
		break ;
	    }
	}
    }
}

/*
 * drain all queues. Called in case of severe mbuf shortage.
 */
void
dummynet_drain()
{
    struct dn_flow_set *fs;
    struct dn_pipe *p;
    struct dn_pkt *pkt;

    heap_free(&ready_heap);
    heap_free(&wfq_ready_heap);
    heap_free(&extract_heap);
    /* remove all references to this pipe from flow_sets */
    for (fs = all_flow_sets; fs; fs= fs->next )
	purge_flow_set(fs, 0);

    for (p = all_pipes; p; p= p->next ) {
	purge_flow_set(&(p->fs), 0);
	for (pkt = p->head ; pkt ; )
	    DN_FREE_PKT(pkt) ;
	p->head = p->tail = NULL ;
    }
}

/*
 * Fully delete a pipe or a queue, cleaning up associated info.
 */
static int 
delete_pipe(struct dn_pipe *p)
{
    int s ;
    struct ip_fw_chain *chain ;

    if (p->pipe_nr == 0 && p->fs.fs_nr == 0)
	return EINVAL ;
    if (p->pipe_nr != 0 && p->fs.fs_nr != 0)
	return EINVAL ;
    if (p->pipe_nr != 0) { /* this is an old-style pipe */
	struct dn_pipe *a, *b;
	struct dn_flow_set *fs;

	/* locate pipe */
	for (a = NULL , b = all_pipes ; b && b->pipe_nr < p->pipe_nr ;
		 a = b , b = b->next) ;
	if (b == NULL || (b->pipe_nr != p->pipe_nr) )
	    return EINVAL ; /* not found */

	s = splimp() ;

	/* unlink from list of pipes */
	if (a == NULL)
	    all_pipes = b->next ;
	else
	    a->next = b->next ;
	/* remove references to this pipe from the ip_fw rules. */
	LIST_FOREACH(chain, &ip_fw_chain_head, next)
	    if (chain->rule->pipe_ptr == &(b->fs))
		chain->rule->pipe_ptr = NULL ;

	/* remove all references to this pipe from flow_sets */
	for (fs = all_flow_sets; fs; fs= fs->next )
	    if (fs->pipe == b) {
		printf("++ ref to pipe %d from fs %d\n",
			p->pipe_nr, fs->fs_nr);
		fs->pipe = NULL ;
		purge_flow_set(fs, 0);
	    }
	fs_remove_from_heap(&ready_heap, &(b->fs));
	purge_pipe(b);	/* remove all data associated to this pipe */
	/* remove reference to here from extract_heap and wfq_ready_heap */
	pipe_remove_from_heap(&extract_heap, b);
	pipe_remove_from_heap(&wfq_ready_heap, b);
	splx(s);
	FREE(b, M_IPFW);
    } else { /* this is a WF2Q queue (dn_flow_set) */
	struct dn_flow_set *a, *b;

	/* locate set */
	for (a = NULL, b = all_flow_sets ; b && b->fs_nr < p->fs.fs_nr ;
		 a = b , b = b->next) ;
	if (b == NULL || (b->fs_nr != p->fs.fs_nr) )
	    return EINVAL ; /* not found */

	s = splimp() ;
	if (a == NULL)
	    all_flow_sets = b->next ;
	else
	    a->next = b->next ;
	/* remove references to this flow_set from the ip_fw rules. */
	LIST_FOREACH(chain, &ip_fw_chain_head, next)
	    if (chain->rule->pipe_ptr == b)
		chain->rule->pipe_ptr = NULL ;

	if (b->pipe != NULL) {
	    /* Update total weight on parent pipe and cleanup parent heaps */
	    b->pipe->sum -= b->weight * b->backlogged ;
	    fs_remove_from_heap(&(b->pipe->not_eligible_heap), b);
	    fs_remove_from_heap(&(b->pipe->scheduler_heap), b);
#if 1	/* XXX should i remove from idle_heap as well ? */
	    fs_remove_from_heap(&(b->pipe->idle_heap), b);
#endif
	}
	purge_flow_set(b, 1);
	splx(s);
    }
    return 0 ;
}

/*
 * helper function used to copy data from kernel in DUMMYNET_GET
 */
static char *
dn_copy_set(struct dn_flow_set *set, char *bp)
{
    int i, copied = 0 ;
    struct dn_flow_queue *q, *qp = (struct dn_flow_queue *)bp;

    for (i = 0 ; i <= set->rq_size ; i++)
	for (q = set->rq[i] ; q ; q = q->next, qp++ ) {
	    if (q->hash_slot != i)
		printf("++ at %d: wrong slot (have %d, "
		    "should be %d)\n", copied, q->hash_slot, i);
	    if (q->fs != set)
		printf("++ at %d: wrong fs ptr (have %p, should be %p)\n",
			i, q->fs, set);
	    copied++ ;
	    bcopy(q, qp, sizeof( *q ) );
	    /* cleanup pointers */
	    qp->next = NULL ;
	    qp->head = qp->tail = NULL ;
	    qp->fs = NULL ;
	}
    if (copied != set->rq_elements)
	printf("++ wrong count, have %d should be %d\n",
	    copied, set->rq_elements);
    return (char *)qp ;
}

static int
dummynet_get(struct sockopt *sopt)
{
    char *buf, *bp ; /* bp is the "copy-pointer" */
    size_t size ;
    struct dn_flow_set *set ;
    struct dn_pipe *p ;
    int s, error=0 ;

    s = splimp();
    /*
     * compute size of data structures: list of pipes and flow_sets.
     */
    for (p = all_pipes, size = 0 ; p ; p = p->next )
	size += sizeof( *p ) +
	    p->fs.rq_elements * sizeof(struct dn_flow_queue);
    for (set = all_flow_sets ; set ; set = set->next )
	size += sizeof ( *set ) +
	    set->rq_elements * sizeof(struct dn_flow_queue);
    buf = _MALLOC(size, M_TEMP, M_DONTWAIT);
    if (buf == 0) {
	splx(s);
	return ENOBUFS ;
    }
    for (p = all_pipes, bp = buf ; p ; p = p->next ) {
	struct dn_pipe *pipe_bp = (struct dn_pipe *)bp ;

	/*
	 * copy pipe descriptor into *bp, convert delay back to ms,
	 * then copy the flow_set descriptor(s) one at a time.
	 * After each flow_set, copy the queue descriptor it owns.
	 */
	bcopy(p, bp, sizeof( *p ) );
	pipe_bp->delay = (pipe_bp->delay * 1000) / hz ;
	/*
	 * XXX the following is a hack based on ->next being the
	 * first field in dn_pipe and dn_flow_set. The correct
	 * solution would be to move the dn_flow_set to the beginning
	 * of struct dn_pipe.
	 */
	pipe_bp->next = (struct dn_pipe *)DN_IS_PIPE ;
	/* clean pointers */
	pipe_bp->head = pipe_bp->tail = NULL ;
	pipe_bp->fs.next = NULL ;
	pipe_bp->fs.pipe = NULL ;
	pipe_bp->fs.rq = NULL ;

	bp += sizeof( *p ) ;
	bp = dn_copy_set( &(p->fs), bp );
    }
    for (set = all_flow_sets ; set ; set = set->next ) {
	struct dn_flow_set *fs_bp = (struct dn_flow_set *)bp ;
	bcopy(set, bp, sizeof( *set ) );
	/* XXX same hack as above */
	fs_bp->next = (struct dn_flow_set *)DN_IS_QUEUE ;
	fs_bp->pipe = NULL ;
	fs_bp->rq = NULL ;
	bp += sizeof( *set ) ;
	bp = dn_copy_set( set, bp );
    }
    splx(s);
    error = sooptcopyout(sopt, buf, size);
    FREE(buf, M_TEMP);
    return error ;
}

/*
 * Handler for the various dummynet socket options (get, flush, config, del)
 */
static int
ip_dn_ctl(struct sockopt *sopt)
{
    int error = 0 ;
    struct dn_pipe *p, tmp_pipe;

    /* Disallow sets in really-really secure mode. */
    if (sopt->sopt_dir == SOPT_SET && securelevel >= 3)
	return (EPERM);

    switch (sopt->sopt_name) {
    default :
	printf("ip_dn_ctl -- unknown option %d", sopt->sopt_name);
	return EINVAL ;

    case IP_DUMMYNET_GET :
	error = dummynet_get(sopt);
	break ;

    case IP_DUMMYNET_FLUSH :
	dummynet_flush() ;
	break ;
    case IP_DUMMYNET_CONFIGURE :
	p = &tmp_pipe ;
	error = sooptcopyin(sopt, p, sizeof *p, sizeof *p);
	if (error)
	    break ;
	error = config_pipe(p);
	break ;

    case IP_DUMMYNET_DEL :	/* remove a pipe or queue */
	p = &tmp_pipe ;
	error = sooptcopyin(sopt, p, sizeof *p, sizeof *p);
	if (error)
	    break ;

	error = delete_pipe(p);
	break ;
    }
    return error ;
}

static void
ip_dn_init(void)
{
    printf("DUMMYNET initialized (010124)\n");
    all_pipes = NULL ;
    all_flow_sets = NULL ;
    ready_heap.size = ready_heap.elements = 0 ;
    ready_heap.offset = 0 ;

    wfq_ready_heap.size = wfq_ready_heap.elements = 0 ;
    wfq_ready_heap.offset = 0 ;

    extract_heap.size = extract_heap.elements = 0 ;
    extract_heap.offset = 0 ;
    ip_dn_ctl_ptr = ip_dn_ctl;
    timeout(dummynet, NULL, 1);
}

static ip_dn_ctl_t *old_dn_ctl_ptr ;

static int
dummynet_modevent(module_t mod, int type, void *data)
{
	int s ;
	switch (type) {
	case MOD_LOAD:
		s = splimp();
		old_dn_ctl_ptr = ip_dn_ctl_ptr;
		ip_dn_init();
		splx(s);
		break;
	case MOD_UNLOAD:
		s = splimp();
		ip_dn_ctl_ptr =  old_dn_ctl_ptr;
		splx(s);
		dummynet_flush();
		break ;
	default:
		break ;
	}
	return 0 ;
}

static moduledata_t dummynet_mod = {
	"dummynet",
	dummynet_modevent,
	NULL
} ;
DECLARE_MODULE(dummynet, dummynet_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
