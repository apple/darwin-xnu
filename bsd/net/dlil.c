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
 *	Copyright (c) 1999 Apple Computer, Inc. 
 *
 *	Data Link Inteface Layer
 *	Author: Ted Walker
 */



#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/dlil.h>
#include <sys/kern_event.h>
#include <sys/kdebug.h>
#include <string.h>

#include <kern/thread.h>
#include <kern/task.h>
#include <net/netisr.h>
#include <net/if_types.h>

#include <machine/machine_routines.h>

#define DBG_LAYER_BEG		DLILDBG_CODE(DBG_DLIL_STATIC, 0)
#define DBG_LAYER_END		DLILDBG_CODE(DBG_DLIL_STATIC, 2)
#define DBG_FNC_DLIL_INPUT      DLILDBG_CODE(DBG_DLIL_STATIC, (1 << 8))
#define DBG_FNC_DLIL_OUTPUT     DLILDBG_CODE(DBG_DLIL_STATIC, (2 << 8))
#define DBG_FNC_DLIL_IFOUT      DLILDBG_CODE(DBG_DLIL_STATIC, (3 << 8))


#define MAX_DL_TAGS 50
#define MAX_DLIL_FILTERS 50
#define MAX_FRAME_TYPE_SIZE 4 /* LONGWORDS */
#define MAX_LINKADDR	    4 /* LONGWORDS */
#define M_NKE M_IFADDR

#define PFILT(x) ((struct dlil_filterq_entry *) (x))->variants.pr_filter
#define IFILT(x) ((struct dlil_filterq_entry *) (x))->variants.if_filter

struct dl_tag_str {
    struct ifnet	*ifp;
    struct if_proto	*proto;
    struct dlil_filterq_head *pr_flt_head;
};


struct dlil_stats_str {
    int	   inject_pr_in1;    
    int	   inject_pr_in2;
    int	   inject_pr_out1;
    int	   inject_pr_out2;
    int	   inject_if_in1;
    int	   inject_if_in2;
    int	   inject_if_out1;
    int	   inject_if_out2;
};


struct dlil_filter_id_str {
    int			      type;
    struct dlil_filterq_head  *head;
    struct dlil_filterq_entry *filter_ptr;
    struct ifnet	      *ifp;
    struct if_proto	      *proto;
};



struct if_family_str {
    TAILQ_ENTRY(if_family_str) if_fam_next;
    u_long	if_family;
    int		refcnt;
    int		flags;

#define DLIL_SHUTDOWN 1

    int (*add_if)(struct ifnet *ifp);
    int (*del_if)(struct ifnet *ifp);
    int (*add_proto)(struct ddesc_head_str *demux_desc_head,
		     struct if_proto  *proto, u_long dl_tag);
    int (*del_proto)(struct if_proto  *proto, u_long dl_tag);
    int (*ifmod_ioctl)(struct ifnet *ifp, u_long command, caddr_t data);
    int (*shutdown)();
};



struct dlil_stats_str dlil_stats;

static
struct dlil_filter_id_str dlil_filters[MAX_DLIL_FILTERS+1];

static
struct dl_tag_str    dl_tag_array[MAX_DL_TAGS+1];

static 
TAILQ_HEAD(, if_family_str) if_family_head;

static		    ifnet_inited = 0;

int dlil_initialized = 0;
decl_simple_lock_data(, dlil_input_lock)
int dlil_input_thread_wakeup = 0;
int dlil_expand_mcl;
static struct mbuf *dlil_input_mbuf_head = NULL;
static struct mbuf *dlil_input_mbuf_tail = NULL;
static struct mbuf *dlil_input_loop_head = NULL;
static struct mbuf *dlil_input_loop_tail = NULL;

static void dlil_input_thread(void);
extern void run_netisr(void);


/*
 * Internal functions.
 */

static 
struct if_family_str *find_family_module(u_long if_family)
{
    struct if_family_str  *mod = NULL;

    TAILQ_FOREACH(mod, &if_family_head, if_fam_next) {
	if (mod->if_family == (if_family & 0xffff)) 
	    break;
    }

    return mod;
}


/*
 * Public functions.
 */

struct ifnet *ifbyfamily(u_long family, short unit)
{
    struct ifnet *ifp;

    TAILQ_FOREACH(ifp, &ifnet, if_link)
	if ((family == ifp->if_family) &&
	    (ifp->if_unit == unit))
	    return ifp;

    return 0;
}

struct if_proto *dlttoproto(dl_tag)
    u_long dl_tag;
{
    return dl_tag_array[dl_tag].proto;
}


static int dlil_ifp_proto_count(struct ifnet * ifp) 
{
    int				count = 0;
    struct if_proto *		proto;
    struct dlil_proto_head *	tmp;

    tmp = (struct dlil_proto_head *) &ifp->proto_head;

    TAILQ_FOREACH(proto, tmp, next)
	count++;

    return count;
}

u_long	ifptodlt(struct ifnet *ifp, u_long proto_family)
{
    struct if_proto *proto;
    struct dlil_proto_head  *tmp = (struct dlil_proto_head *) &ifp->proto_head;


    TAILQ_FOREACH(proto, tmp, next)
	if (proto->protocol_family == proto_family)
	    return proto->dl_tag;

    return 0;
}

    
int  dlil_find_dltag(u_long if_family, short unit, u_long proto_family, u_long *dl_tag)
{
    struct ifnet  *ifp;

    ifp = ifbyfamily(if_family, unit);
    if (!ifp)
	return ENOENT;

    *dl_tag = ifptodlt(ifp, proto_family);
    if (*dl_tag == 0)
	return EPROTONOSUPPORT;
    else
	return 0;
}


int dlil_get_next_dl_tag(u_long current_tag, struct dl_tag_attr_str *next)
{
    int i;

    for (i = (current_tag+1); i < MAX_DL_TAGS; i++)
	if (dl_tag_array[i].ifp) {
	    next->dl_tag   = i;
	    next->if_flags = dl_tag_array[i].ifp->if_flags;
	    next->if_unit  = dl_tag_array[i].ifp->if_unit;
	    next->protocol_family = dl_tag_array[i].proto->protocol_family;
	    next->if_family = dl_tag_array[i].ifp->if_family;
	    return 0;
	}

    /*
     * If we got here, there are no more entries
     */

    return ENOENT;
} 

void dlil_post_msg(struct ifnet *ifp, u_long event_subclass, u_long event_code, 
		   struct net_event_data *event_data, u_long event_data_len) 
{
    struct net_event_data  	ev_data;
    struct kev_msg  		ev_msg;

    /* 
     * a net event always start with a net_event_data structure
     * but the caller can generate a simple net event or
     * provide a longer event structure to post
     */
    
    ev_msg.vendor_code    = KEV_VENDOR_APPLE;
    ev_msg.kev_class      = KEV_NETWORK_CLASS;
    ev_msg.kev_subclass   = event_subclass;
    ev_msg.event_code 	  = event_code;    
    
    if (event_data == 0) {
        event_data = &ev_data;
        event_data_len = sizeof(struct net_event_data);
    }
    
    strncpy(&event_data->if_name[0], ifp->if_name, IFNAMSIZ);
    event_data->if_family = ifp->if_family;
    event_data->if_unit   = (unsigned long) ifp->if_unit;

    ev_msg.dv[0].data_length = event_data_len;
    ev_msg.dv[0].data_ptr    = event_data;	
    ev_msg.dv[1].data_length = 0;

    kev_post_msg(&ev_msg);
}



void
dlil_init()
{
    int i;

    printf("dlil_init\n");

    TAILQ_INIT(&if_family_head);
    for (i=0; i < MAX_DL_TAGS; i++)
	dl_tag_array[i].ifp = 0;

    for (i=0; i < MAX_DLIL_FILTERS; i++)
	dlil_filters[i].type = 0;

    bzero(&dlil_stats, sizeof(dlil_stats));

    simple_lock_init(&dlil_input_lock);

    /*
     * Start up the dlil input thread once everything is initialized
     */
    (void) kernel_thread(kernel_task, dlil_input_thread);
}


u_long get_new_filter_id()
{
    u_long i;

    for (i=1; i < MAX_DLIL_FILTERS; i++)
	if (dlil_filters[i].type == 0)
	    return i;
 
    return 0;
}


int   dlil_attach_interface_filter(struct ifnet *ifp,
				   struct dlil_if_flt_str  *if_filter,
				   u_long		   *filter_id,
				   int			   insertion_point)
{
    int s;
    int retval;
    struct dlil_filterq_entry	*tmp_ptr;
    struct dlil_filterq_entry	*if_filt;
    struct dlil_filterq_head *fhead = (struct dlil_filterq_head *) &ifp->if_flt_head;
    boolean_t funnel_state;


    MALLOC(tmp_ptr, struct dlil_filterq_entry *, sizeof(*tmp_ptr), M_NKE, M_WAITOK);
    if (tmp_ptr == NULL)
	return (ENOBUFS);

    bcopy((caddr_t) if_filter, (caddr_t) &tmp_ptr->variants.if_filter, 
	  sizeof(struct dlil_if_flt_str));

    funnel_state = thread_funnel_set(network_flock, TRUE);

    s = splnet();

    if (insertion_point != DLIL_LAST_FILTER) {
	TAILQ_FOREACH(if_filt, fhead, que)
	    if (insertion_point == if_filt->filter_id) {
		TAILQ_INSERT_BEFORE(if_filt, tmp_ptr, que);
		break;
	    }
    }
    else 
	TAILQ_INSERT_TAIL(fhead, tmp_ptr, que);

    if (*filter_id = get_new_filter_id()) {
	dlil_filters[*filter_id].filter_ptr = tmp_ptr;
	dlil_filters[*filter_id].head = (struct dlil_filterq_head *) &ifp->if_flt_head;
	dlil_filters[*filter_id].type = DLIL_IF_FILTER;
	dlil_filters[*filter_id].ifp = ifp;
	tmp_ptr->filter_id = *filter_id;
	tmp_ptr->type	   = DLIL_IF_FILTER;
	retval = 0;
    }
    else {
	kprintf("dlil_attach_interface_filter - can't alloc filter_id\n");
	TAILQ_REMOVE(fhead, tmp_ptr, que);
	FREE(tmp_ptr, M_NKE);
	retval = ENOMEM;
    }

    splx(s);
    thread_funnel_set(network_flock, funnel_state);
    return retval;
}


int   dlil_attach_protocol_filter(u_long			 dl_tag,
				  struct dlil_pr_flt_str	 *pr_filter,
				  u_long			 *filter_id,
				  int				 insertion_point)
{
    struct dlil_filterq_entry	*tmp_ptr;
    struct dlil_filterq_entry	*pr_filt;
    int s;
    int retval;
    boolean_t funnel_state;

    if (dl_tag > MAX_DL_TAGS)
	return ERANGE;

    if (dl_tag_array[dl_tag].ifp == 0)
	return ENOENT;

    MALLOC(tmp_ptr, struct dlil_filterq_entry *, sizeof(*tmp_ptr), M_NKE, M_WAITOK);
    if (tmp_ptr == NULL)
	return (ENOBUFS);

    bcopy((caddr_t) pr_filter, (caddr_t) &tmp_ptr->variants.pr_filter, 
	  sizeof(struct dlil_pr_flt_str));

    funnel_state = thread_funnel_set(network_flock, TRUE);

    s = splnet();
    if (insertion_point != DLIL_LAST_FILTER) {
	TAILQ_FOREACH(pr_filt, dl_tag_array[dl_tag].pr_flt_head, que)
	    if (insertion_point == pr_filt->filter_id) {
		TAILQ_INSERT_BEFORE(pr_filt, tmp_ptr, que);
		break;
	    }
    }
    else 
	TAILQ_INSERT_TAIL(dl_tag_array[dl_tag].pr_flt_head, tmp_ptr, que);

    
    if (*filter_id = get_new_filter_id()) {
	dlil_filters[*filter_id].filter_ptr = tmp_ptr; 
	dlil_filters[*filter_id].head = dl_tag_array[dl_tag].pr_flt_head;
	dlil_filters[*filter_id].type = DLIL_PR_FILTER;
	dlil_filters[*filter_id].proto = dl_tag_array[dl_tag].proto;
	dlil_filters[*filter_id].ifp   = dl_tag_array[dl_tag].ifp;
	tmp_ptr->filter_id = *filter_id;
	tmp_ptr->type	   = DLIL_PR_FILTER;
	retval = 0;
    }
    else {
	kprintf("dlil_attach_protocol_filter - can't alloc filter_id\n");
	TAILQ_REMOVE(dl_tag_array[dl_tag].pr_flt_head, tmp_ptr, que);
	FREE(tmp_ptr, M_NKE);
	retval =  ENOMEM;
    }

    splx(s);
    thread_funnel_set(network_flock, funnel_state);
    return retval;
}


int
dlil_detach_filter(u_long	filter_id)
{
    struct dlil_filter_id_str *flt;
    int s;
    boolean_t funnel_state;

    if (filter_id > MAX_DLIL_FILTERS) {
	kprintf("dlil_detach_filter - Bad filter_id value %d\n", filter_id);
	return ERANGE;
    }

    funnel_state = thread_funnel_set(network_flock, TRUE);
    s = splnet();
    flt = &dlil_filters[filter_id];
    if (flt->type == 0) {
	kprintf("dlil_detach_filter - no such filter_id %d\n", filter_id);
	thread_funnel_set(network_flock, funnel_state);
	return ENOENT;
    }


    if (flt->type == DLIL_IF_FILTER) {
	if (IFILT(flt->filter_ptr).filter_detach)
	    (*IFILT(flt->filter_ptr).filter_detach)(IFILT(flt->filter_ptr).cookie);
    }
    else {
	if (flt->type == DLIL_PR_FILTER) {
	    if (PFILT(flt->filter_ptr).filter_detach)
		(*PFILT(flt->filter_ptr).filter_detach)(PFILT(flt->filter_ptr).cookie);
	}
    }

    TAILQ_REMOVE(flt->head, flt->filter_ptr, que);
    FREE(flt->filter_ptr, M_NKE);
    flt->type = 0;
    splx(s);
    thread_funnel_set(network_flock, funnel_state);
    return 0;
}


void
dlil_input_thread_continue(void)
{
    while (1) {
        struct mbuf *m, *m_loop;
	int expand_mcl;

        usimple_lock(&dlil_input_lock);
        m = dlil_input_mbuf_head;
        dlil_input_mbuf_head = NULL;
        dlil_input_mbuf_tail = NULL;
        m_loop = dlil_input_loop_head;
        dlil_input_loop_head = NULL;
        dlil_input_loop_tail = NULL;
        usimple_unlock(&dlil_input_lock);
	
	MBUF_LOCK();
	expand_mcl = dlil_expand_mcl;
	dlil_expand_mcl = 0;
	MBUF_UNLOCK();
	if (expand_mcl) {
		caddr_t	p;
		MCLALLOC(p, M_WAIT);
		if (p) MCLFREE(p);
	}

        /*
         * NOTE warning %%% attention !!!!
         * We should think about putting some thread starvation safeguards if 
         * we deal with long chains of packets.
         */
        while (m) {
            struct mbuf *m0 = m->m_nextpkt;
            void *header = m->m_pkthdr.header;

            m->m_nextpkt = NULL;
            m->m_pkthdr.header = NULL;
            (void) dlil_input_packet(m->m_pkthdr.rcvif, m, header);
            m = m0;
        }
        m = m_loop;
        while (m) {
            struct mbuf *m0 = m->m_nextpkt;
            void *header = m->m_pkthdr.header;
            struct ifnet *ifp = (struct ifnet *) m->m_pkthdr.aux;

            m->m_nextpkt = NULL;
            m->m_pkthdr.header = NULL;
            m->m_pkthdr.aux = NULL;
            (void) dlil_input_packet(ifp, m, header);
            m = m0;
        }

        if (netisr != 0)
            run_netisr();

	if (dlil_input_mbuf_head == NULL && 
            dlil_input_loop_head == NULL &&
            netisr == 0) {
            assert_wait(&dlil_input_thread_wakeup, THREAD_UNINT);
#if defined (__i386__)
            thread_block(0);
#else
            thread_block(dlil_input_thread_continue);
#endif
        /* NOTREACHED */
        }
    }
}

void dlil_input_thread(void)
{
    register thread_t self = current_thread();
    extern void stack_privilege(thread_t thread);

    printf("dlil_input_thread %x\n", self);

    /*
     *      Make sure that this thread
     *      always has a kernel stack, and
     *      bind it to the master cpu.
     */
    stack_privilege(self);
    ml_thread_policy(current_thread(), MACHINE_GROUP, (MACHINE_NETWORK_GROUP|MACHINE_NETWORK_NETISR));

    /* The dlil thread is always funneled */
    thread_funnel_set(network_flock, TRUE);
    dlil_initialized = 1;
    dlil_input_thread_continue();
}

int
dlil_input(struct ifnet  *ifp, struct mbuf *m_head, struct mbuf *m_tail)
{   
    /* WARNING
     * Because of loopbacked multicast we cannot stuff the ifp in
     * the rcvif of the packet header: loopback has its own dlil
     * input queue
     */
  
    usimple_lock(&dlil_input_lock);
    if (ifp->if_type != IFT_LOOP) {
        if (dlil_input_mbuf_head == NULL)
            dlil_input_mbuf_head = m_head;
        else if (dlil_input_mbuf_tail != NULL)
            dlil_input_mbuf_tail->m_nextpkt = m_head;
        dlil_input_mbuf_tail = m_tail ? m_tail : m_head;
    } else {
        if (dlil_input_loop_head == NULL)
            dlil_input_loop_head = m_head;
        else if (dlil_input_loop_tail != NULL)
            dlil_input_loop_tail->m_nextpkt = m_head;
        dlil_input_loop_tail = m_tail ? m_tail : m_head;
    }   
    usimple_unlock(&dlil_input_lock);

    wakeup((caddr_t)&dlil_input_thread_wakeup);
         
    return 0; 
}

int
dlil_input_packet(struct ifnet  *ifp, struct mbuf *m, 
	   char *frame_header)
{
    struct ifnet		 *orig_ifp = 0;
    struct dlil_filterq_entry	 *tmp;
    int				 retval;
    struct if_proto		 *ifproto = 0;
    struct if_proto		 *proto;
    struct dlil_filterq_head *fhead = (struct dlil_filterq_head *) &ifp->if_flt_head;


    KERNEL_DEBUG(DBG_FNC_DLIL_INPUT | DBG_FUNC_START,0,0,0,0,0);

   /*
    * Run interface filters
    */

    while (orig_ifp != ifp) {
	orig_ifp = ifp;
	
	TAILQ_FOREACH_REVERSE(tmp, fhead, que, dlil_filterq_head) {
	    if (IFILT(tmp).filter_if_input) {
		retval = (*IFILT(tmp).filter_if_input)(IFILT(tmp).cookie,
						       &ifp,
						       &m,
						       &frame_header);
		if (retval) {
		    if (retval == EJUSTRETURN)
			return 0;
		    else {
			m_freem(m);
			return retval;
		    }
		}
	    }

	    if (ifp != orig_ifp)
		break;
	}
    }

    ifp->if_lastchange = time;
 
    /*
     * Call family demux module. If the demux module finds a match
     * for the frame it will fill-in the ifproto pointer.
     */

    retval = (*ifp->if_demux)(ifp, m, frame_header, &ifproto );

    if (m->m_flags & (M_BCAST|M_MCAST))
	ifp->if_imcasts++;
    
    if ((retval) && (retval != EJUSTRETURN) && (ifp->offercnt)) {
	/*
	 * No match was found, look for any offers.
	 */
	struct dlil_proto_head	*tmp = (struct dlil_proto_head *) &ifp->proto_head;
	TAILQ_FOREACH(proto, tmp, next) {
	    if ((proto->dl_offer) && (proto->dl_offer(m, frame_header) == 0)) {
		ifproto = proto;
		retval = 0;
		break;
	    }
	}
    }

    if (retval) {
	if (retval != EJUSTRETURN) {
	    m_freem(m);
	    return retval;
	}
	else
	    return 0;
    } 
    else
	if (ifproto == 0) {
	    printf("ERROR - dlil_input - if_demux didn't return an if_proto pointer\n");
	    m_freem(m);
	    return 0;
	}

/*
 * Call any attached protocol filters.
 */

    TAILQ_FOREACH_REVERSE(tmp, &ifproto->pr_flt_head, que, dlil_filterq_head) { 
	if (PFILT(tmp).filter_dl_input) { 
	    retval = (*PFILT(tmp).filter_dl_input)(PFILT(tmp).cookie, 
						   &m,	
						   &frame_header,
						   &ifp);

	    if (retval) {
		if (retval == EJUSTRETURN)
		    return 0;
		else {
		    m_freem(m);
		    return retval;
		}
	    }
	} 
    }		  



    retval = (*ifproto->dl_input)(m, frame_header, 
				  ifp, ifproto->dl_tag, 
				  TRUE); 
    
    if (retval == EJUSTRETURN)
	retval = 0;
    else 
	if (retval)
	    m_freem(m);

    KERNEL_DEBUG(DBG_FNC_DLIL_INPUT | DBG_FUNC_END,0,0,0,0,0);
    return retval;
}



void ether_input(ifp, eh, m)
    struct ifnet *ifp;
    struct ether_header	 *eh;
    struct mbuf		 *m;

{
    kprintf("Someone is calling ether_input!!\n");

    dlil_input(ifp, m, NULL);
}


int
dlil_event(struct ifnet *ifp, struct kern_event_msg *event)
{
    struct dlil_filterq_entry	 *filt;
    int				 retval = 0;
    struct ifnet                 *orig_ifp = 0;
    struct if_proto		 *proto;
    struct dlil_filterq_head *fhead = (struct dlil_filterq_head *) &ifp->if_flt_head;
    struct kev_msg               kev_msg;
    struct dlil_proto_head	*tmp = (struct dlil_proto_head *) &ifp->proto_head;
    boolean_t funnel_state;


    funnel_state = thread_funnel_set(network_flock, TRUE);

    while (orig_ifp != ifp) {
	orig_ifp = ifp;

	TAILQ_FOREACH_REVERSE(filt, fhead, que, dlil_filterq_head) {
	     if (IFILT(filt).filter_if_event) {
		  retval = (*IFILT(filt).filter_if_event)(IFILT(filt).cookie,
							 &ifp,
							 &event);
		  
		  if (retval) {
                        (void) thread_funnel_set(network_flock, funnel_state);
		       if (retval == EJUSTRETURN)
			    return 0;
		       else 
			    return retval;
		  }
	     }

	     if (ifp != orig_ifp)
		  break;
	}
    }


    /*
     * Call Interface Module event hook, if any.
     */

    if (ifp->if_event) {
	 retval = ifp->if_event(ifp, (caddr_t) event);

	 if (retval) {
	      (void) thread_funnel_set(network_flock, funnel_state);

	      if (retval == EJUSTRETURN)
		   return 0;
	      else 
		   return retval;
	 }
    }

    /*
     * Call dl_event entry point for all protocols attached to this interface
     */

    TAILQ_FOREACH(proto, tmp, next) {
	/*
	 * Call any attached protocol filters.
	 */

	 TAILQ_FOREACH_REVERSE(filt, &proto->pr_flt_head, que, dlil_filterq_head) { 
	      if (PFILT(filt).filter_dl_event) { 
		   retval = (*PFILT(filt).filter_dl_event)(PFILT(filt).cookie, 
							  event);

		   if (retval) {
                        (void) thread_funnel_set(network_flock, funnel_state);
			if (retval == EJUSTRETURN)
			     return 0;
			else
			     return retval;
		   }
	      } 
	 }		  


	 /*
	  * Finally, call the dl_event entry point (if any)
	  */

	 if (proto->dl_event)
	      retval = (*proto->dl_event)(event, proto->dl_tag);

	 if (retval == EJUSTRETURN) {
	      (void) thread_funnel_set(network_flock, funnel_state);
	      return 0;
	 }
    }
	      

    /*
     * Now, post this event to the Kernel Event message queue
     */

    kev_msg.vendor_code    = event->vendor_code;
    kev_msg.kev_class      = event->kev_class;
    kev_msg.kev_subclass   = event->kev_subclass;
    kev_msg.event_code     = event->event_code;
    kev_msg.dv[0].data_ptr = &event->event_data[0];
    kev_msg.dv[0].data_length = event->total_size - KEV_MSG_HEADER_SIZE;
    kev_msg.dv[1].data_length = 0;

    kev_post_msg(&kev_msg);

    (void) thread_funnel_set(network_flock, funnel_state);
    return 0;
}



int
dlil_output(u_long		dl_tag,
	    struct mbuf		*m,
	    caddr_t		route,
	    struct sockaddr	*dest,
	    int			raw
	    )
{
    char			 *frame_type;
    char			 *dst_linkaddr;
    struct ifnet		 *orig_ifp = 0;
    struct ifnet		 *ifp;
    struct if_proto		 *proto;
    struct dlil_filterq_entry	 *tmp;
    int				 retval = 0;
    char			 frame_type_buffer[MAX_FRAME_TYPE_SIZE * 4];
    char			 dst_linkaddr_buffer[MAX_LINKADDR * 4];
    struct dlil_filterq_head	 *fhead;


    KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_START,0,0,0,0,0);

    /*
     * Temporary hackery until all the existing protocols can become fully
     * "dl_tag aware". Some things only have the ifp, so this handles that
     * case for the time being.
     */

    if (dl_tag > MAX_DL_TAGS) {
	/* dl_tag is really an ifnet pointer! */

	ifp = (struct ifnet *) dl_tag;
	dl_tag = ifp->if_data.default_proto;
	if (dl_tag)
	    proto = dl_tag_array[dl_tag].proto;
	else
	    retval = ENOENT;
    }
    else {
	if ((dl_tag == 0) || (dl_tag_array[dl_tag].ifp == 0))
	    retval = ENOENT;
	else {
	    ifp = dl_tag_array[dl_tag].ifp;
	    proto = dl_tag_array[dl_tag].proto;
	}
    }
    
    if (retval) {
	m_freem(m);
	return retval;
    }

    frame_type	   = frame_type_buffer;
    dst_linkaddr   = dst_linkaddr_buffer;

    fhead = (struct dlil_filterq_head *) &ifp->if_flt_head;

    if ((raw == 0) && (proto->dl_pre_output)) {
	retval = (*proto->dl_pre_output)(ifp, &m, dest, route, 
					 frame_type, dst_linkaddr, dl_tag);
	if (retval) {
	    if (retval == EJUSTRETURN)
		return 0;
	    else {
		m_freem(m);
		return retval;
	    }
	}
    }
    
/*
 * Run any attached protocol filters.
 */

    if (TAILQ_EMPTY(dl_tag_array[dl_tag].pr_flt_head) == 0) {
	TAILQ_FOREACH(tmp, dl_tag_array[dl_tag].pr_flt_head, que) {
	    if (PFILT(tmp).filter_dl_output) {
		retval = (*PFILT(tmp).filter_dl_output)(PFILT(tmp).cookie, 
							 &m, &ifp, &dest, dst_linkaddr, frame_type);
		if (retval) {
		    if (retval == EJUSTRETURN)
			return 0;
		    else {
			m_freem(m);
			return retval;
		    }
		}
	    }
	}
    }


/*
 * Call framing module 
 */
    if ((raw == 0) && (ifp->if_framer)) {
	retval = (*ifp->if_framer)(ifp, &m, dest, dst_linkaddr, frame_type);
	if (retval) {
	    if (retval == EJUSTRETURN)
		return 0;
	    else
	    {
		m_freem(m);
		return retval;
	    }
	}
    }

#if BRIDGE
    if (do_bridge) {
	struct mbuf *m0 = m ;
	
	if (m->m_pkthdr.rcvif)
	    m->m_pkthdr.rcvif = NULL ;
	ifp = bridge_dst_lookup(m);
	bdg_forward(&m0, ifp);
	if (m0)
	    m_freem(m0);

	return 0;
    }
#endif


/* 
 * Let interface filters (if any) do their thing ...
 */

    fhead = (struct dlil_filterq_head *) &ifp->if_flt_head;
    if (TAILQ_EMPTY(fhead) == 0) {
	while (orig_ifp != ifp) {
	    orig_ifp = ifp;
	    TAILQ_FOREACH(tmp, fhead, que) {
		if (IFILT(tmp).filter_if_output) {
		    retval = (*IFILT(tmp).filter_if_output)(IFILT(tmp).cookie,
							     &ifp,
							     &m);
		    if (retval) {
			if (retval == EJUSTRETURN)
			    return 0;
			else {
			    m_freem(m);
			    return retval;
			}
		    }

		}
		
		if (ifp != orig_ifp)
		    break;
	    }
	}
    }

/*
 * Finally, call the driver.
 */

    KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_START, 0,0,0,0,0);
    retval = (*ifp->if_output)(ifp, m);
    KERNEL_DEBUG(DBG_FNC_DLIL_IFOUT | DBG_FUNC_END, 0,0,0,0,0);

    KERNEL_DEBUG(DBG_FNC_DLIL_OUTPUT | DBG_FUNC_END,0,0,0,0,0);

    if ((retval == 0) || (retval == EJUSTRETURN))
	return 0;
    else 
	return retval;
}


int
dlil_ioctl(u_long	proto_fam,
	   struct ifnet *ifp,
	   u_long	ioctl_code,
	   caddr_t	ioctl_arg)
{
     struct dlil_filterq_entry	 *tmp;
     struct dlil_filterq_head	 *fhead;
     int			 retval  = EOPNOTSUPP;
     int                         retval2 = EOPNOTSUPP;
     u_long		         dl_tag;
     struct if_family_str    *if_family;


     if (proto_fam) {
	  retval = dlil_find_dltag(ifp->if_family, ifp->if_unit,
				   proto_fam, &dl_tag);

	  if (retval == 0) {
	       if (dl_tag_array[dl_tag].ifp != ifp)
		    return ENOENT;
	
/*
 * Run any attached protocol filters.
 */
	       TAILQ_FOREACH(tmp, dl_tag_array[dl_tag].pr_flt_head, que) {
		    if (PFILT(tmp).filter_dl_ioctl) {
			 retval = 
			      (*PFILT(tmp).filter_dl_ioctl)(PFILT(tmp).cookie, 
							    dl_tag_array[dl_tag].ifp,
							    ioctl_code, 
							    ioctl_arg);
								   
			 if (retval) {
			      if (retval == EJUSTRETURN)
				   return 0;
			      else
				   return retval;
			 }
		    }
	       }

	       if (dl_tag_array[dl_tag].proto->dl_ioctl)
		    retval =  
			 (*dl_tag_array[dl_tag].proto->dl_ioctl)(dl_tag,
								 dl_tag_array[dl_tag].ifp, 
								 ioctl_code, 
								 ioctl_arg);
	       else
		    retval = EOPNOTSUPP;
	  }
	  else
	       retval = 0;
     }

     if ((retval) && (retval != EOPNOTSUPP)) {
	  if (retval == EJUSTRETURN)
	       return 0;
	  else
	       return retval;
     }


     fhead = (struct dlil_filterq_head *) &ifp->if_flt_head;
     TAILQ_FOREACH(tmp, fhead, que) {
	  if (IFILT(tmp).filter_if_ioctl) {
	       retval2 = (*IFILT(tmp).filter_if_ioctl)(IFILT(tmp).cookie, ifp,
						       ioctl_code, ioctl_arg);
	       if (retval2) {
		    if (retval2 == EJUSTRETURN)
			 return 0;
		    else
			 return retval2;
	       }
	  }
     }


     if_family = find_family_module(ifp->if_family);
     if ((if_family) && (if_family->ifmod_ioctl)) {
	  retval2 = (*if_family->ifmod_ioctl)(ifp, ioctl_code, ioctl_arg);

	  if ((retval2) && (retval2 != EOPNOTSUPP)) {
	       if (retval2 == EJUSTRETURN)
		    return 0;
	       else
		    return retval;
	  }

	  if (retval == EOPNOTSUPP)
	       retval = retval2;
     }

     if (ifp->if_ioctl) 
	  retval2 = (*ifp->if_ioctl)(ifp, ioctl_code, ioctl_arg);

     if (retval == EOPNOTSUPP) 
	  return retval2;
     else {
	  if (retval2 == EOPNOTSUPP)
	       return 0;
	  else
	       return retval2;
     }
}


int
dlil_attach_protocol(struct dlil_proto_reg_str	 *proto,
		     u_long			 *dl_tag)
{
    struct ifnet     *ifp;
    struct if_proto  *ifproto;
    u_long	     i;
    struct if_family_str *if_family;
    int		     error;
    struct dlil_proto_head  *tmp;
    struct kev_dl_proto_data	ev_pr_data;
    int	 s;
    boolean_t funnel_state;


    if ((proto->protocol_family == 0) || (proto->interface_family == 0))
	return EINVAL;

    funnel_state = thread_funnel_set(network_flock, TRUE);
    s = splnet();
    if_family = find_family_module(proto->interface_family);
    if ((!if_family) || (if_family->flags & DLIL_SHUTDOWN)) {
	kprintf("dlil_attach_protocol -- no interface family module %d", 
	       proto->interface_family);
	splx(s);
	thread_funnel_set(network_flock, funnel_state);
	return ENOENT;
    }

    ifp = ifbyfamily(proto->interface_family, proto->unit_number);
    if (!ifp) {
	kprintf("dlil_attach_protocol -- no such interface %d unit %d\n", 
	       proto->interface_family, proto->unit_number);
	splx(s);
	thread_funnel_set(network_flock, funnel_state);
	return ENOENT;
    }

    if (dlil_find_dltag(proto->interface_family, proto->unit_number,
			proto->protocol_family, &i) == 0) {
	 thread_funnel_set(network_flock, funnel_state);
	 return EEXIST;
    }

    for (i=1; i < MAX_DL_TAGS; i++)
	if (dl_tag_array[i].ifp == 0)
	    break;

    if (i >= MAX_DL_TAGS) {
	splx(s);
	thread_funnel_set(network_flock, funnel_state);
	return ENOMEM;
    }

    /*
     * Allocate and init a new if_proto structure
     */

    ifproto = _MALLOC(sizeof(struct if_proto), M_IFADDR, M_WAITOK);
    if (!ifproto) {
	printf("ERROR - DLIL failed if_proto allocation\n");
	thread_funnel_set(network_flock, funnel_state);
	return ENOMEM;
    }
    
    bzero(ifproto, sizeof(struct if_proto));

    dl_tag_array[i].ifp = ifp;
    dl_tag_array[i].proto = ifproto;
    dl_tag_array[i].pr_flt_head = &ifproto->pr_flt_head;
    ifproto->dl_tag = i;
    *dl_tag = i;

    if (proto->default_proto) {
	if (ifp->if_data.default_proto == 0)
	    ifp->if_data.default_proto = i;
	else 
	    printf("ERROR - dlil_attach_protocol -- Attempt to attach more than one default protocol\n");
    }

    ifproto->protocol_family	= proto->protocol_family;
    ifproto->dl_input		= proto->input;
    ifproto->dl_pre_output	= proto->pre_output;
    ifproto->dl_event		= proto->event;
    ifproto->dl_offer		= proto->offer;
    ifproto->dl_ioctl		= proto->ioctl;
    ifproto->ifp		= ifp;
    TAILQ_INIT(&ifproto->pr_flt_head);

    /*
     * Call family module add_proto routine so it can refine the
     * demux descriptors as it wishes.
     */
    error = (*if_family->add_proto)(&proto->demux_desc_head, ifproto, *dl_tag);
    if (error) {
	dl_tag_array[*dl_tag].ifp = 0;
	FREE(ifproto, M_IFADDR);
	splx(s);
	thread_funnel_set(network_flock, funnel_state);
	return error;
    }

    /*
     * Add to if_proto list for this interface
     */

    tmp = (struct dlil_proto_head *) &ifp->proto_head;
    TAILQ_INSERT_TAIL(tmp, ifproto, next);
    ifp->refcnt++;
    if (ifproto->dl_offer)
	ifp->offercnt++;

    /* the reserved field carries the number of protocol still attached (subject to change) */
    ev_pr_data.proto_family = proto->protocol_family;
    ev_pr_data.proto_remaining_count = dlil_ifp_proto_count(ifp);
    dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_PROTO_ATTACHED, 
		  (struct net_event_data *)&ev_pr_data, 
		  sizeof(struct kev_dl_proto_data));

    splx(s);
    thread_funnel_set(network_flock, funnel_state);
    return 0;
}



int
dlil_detach_protocol(u_long	dl_tag)
{
    struct ifnet    *ifp;
    struct ifnet    *orig_ifp=0;
    struct if_proto *proto;
    struct dlil_proto_head  *tmp; 
    struct if_family_str   *if_family;
    struct dlil_filterq_entry *filter;
    int s, retval;
    struct dlil_filterq_head *fhead;
    struct kev_dl_proto_data	ev_pr_data;
    boolean_t funnel_state;


    if (dl_tag > MAX_DL_TAGS) 
	return ERANGE;

    funnel_state = thread_funnel_set(network_flock, TRUE);

    s = splnet();
    if (dl_tag_array[dl_tag].ifp == 0) {
	splx(s);
	thread_funnel_set(network_flock, funnel_state);
	return ENOENT;
    }

    ifp = dl_tag_array[dl_tag].ifp;
    proto = dl_tag_array[dl_tag].proto;

    if_family = find_family_module(ifp->if_family);
    if (if_family == NULL) {
	 splx(s);
	 thread_funnel_set(network_flock, funnel_state);
	 return ENOENT;
    }

    tmp = (struct dlil_proto_head *) &ifp->proto_head;

    /*
     * Call family module del_proto
     */

    (*if_family->del_proto)(proto, dl_tag);


    /*
     * Remove and deallocate any attached protocol filters
     */

    while (filter = TAILQ_FIRST(&proto->pr_flt_head)) 
	dlil_detach_filter(filter->filter_id);
    
    if (proto->dl_offer)
	ifp->offercnt--;

    if (ifp->if_data.default_proto == dl_tag)
	ifp->if_data.default_proto = 0;
    dl_tag_array[dl_tag].ifp = 0;
	
    /* the reserved field carries the number of protocol still attached (subject to change) */
    ev_pr_data.proto_family   = proto->protocol_family;
    TAILQ_REMOVE(tmp, proto, next);
    FREE(proto, M_IFADDR);

    ifp->refcnt--;
    ev_pr_data.proto_remaining_count = dlil_ifp_proto_count(ifp);
    dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_PROTO_DETACHED, 
		  (struct net_event_data *)&ev_pr_data, 
		  sizeof(struct kev_dl_proto_data));

    if (ifp->refcnt == 0 && (ifp->if_eflags & IFEF_DETACH_DISABLED) == 0) {
	if (ifp->if_flags & IFF_UP) 
	    printf("WARNING - dlil_detach_protocol - ifp refcnt 0, but IF still up\n");

	TAILQ_REMOVE(&ifnet, ifp, if_link);

	(*if_family->del_if)(ifp);

	if (--if_family->refcnt == 0) {
	    if (if_family->shutdown)
		(*if_family->shutdown)();
	    
	    TAILQ_REMOVE(&if_family_head, if_family, if_fam_next);
	    FREE(if_family, M_IFADDR);
	}

	fhead = (struct dlil_filterq_head *) &ifp->if_flt_head;
	while (orig_ifp != ifp) {
	    orig_ifp = ifp;

	    TAILQ_FOREACH(filter, fhead, que) {
		if (IFILT(filter).filter_if_free) {
		    retval = (*IFILT(filter).filter_if_free)(IFILT(filter).cookie, ifp);
		    if (retval) {
			splx(s);
			thread_funnel_set(network_flock, funnel_state);
			return 0;
		    }
		}
		if (ifp != orig_ifp)
		    break;
	    }
	}
	
        dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_IF_DETACHED, 0, 0);

	(*ifp->if_free)(ifp);
    }

    splx(s);
    thread_funnel_set(network_flock, funnel_state);
    return 0;
}





int
dlil_if_attach(struct ifnet	*ifp)
{
    u_long		    interface_family = ifp->if_family;
    struct if_family_str    *if_family;
    struct dlil_proto_head  *tmp;
    int			    stat;
    int s;
    boolean_t funnel_state;

    funnel_state = thread_funnel_set(network_flock, TRUE);
    s = splnet();
    if (ifnet_inited == 0) {
	TAILQ_INIT(&ifnet);
	ifnet_inited = 1;
    }

    if_family = find_family_module(interface_family);

    if ((!if_family) || (if_family->flags & DLIL_SHUTDOWN)) {
	splx(s);
	kprintf("Attempt to attach interface without family module - %d\n", 
	       interface_family);
	thread_funnel_set(network_flock, funnel_state);
	return ENODEV;
    }


    /*
     * Call the family module to fill in the appropriate fields in the
     * ifnet structure.
     */

    stat = (*if_family->add_if)(ifp);
    if (stat) {
	splx(s);
	kprintf("dlil_if_attach -- add_if failed with %d\n", stat);
	thread_funnel_set(network_flock, funnel_state);
	return stat;
    }

    /*
     * Add the ifp to the interface list.
     */

    tmp = (struct dlil_proto_head *) &ifp->proto_head;
    TAILQ_INIT(tmp);
    
    ifp->if_data.default_proto = 0;
    ifp->refcnt = 1;
    ifp->offercnt = 0;
    TAILQ_INIT(&ifp->if_flt_head);
    old_if_attach(ifp);
    if_family->refcnt++;

    dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_IF_ATTACHED, 0, 0);

    splx(s);
    thread_funnel_set(network_flock, funnel_state);
    return 0;
}


int
dlil_if_detach(struct ifnet *ifp)
{
    struct if_proto  *proto;
    struct dlil_filterq_entry *if_filter;
    struct if_family_str    *if_family;
    struct dlil_filterq_head *fhead = (struct dlil_filterq_head *) &ifp->if_flt_head;
    int s;
    struct kev_msg   ev_msg;
    boolean_t funnel_state;

    funnel_state = thread_funnel_set(network_flock, TRUE);
    s = splnet();
    if (ifp->if_flags & IFF_UP)
	printf("WARNING - dlil_if_detach called for UP interface\n");

    if_family = find_family_module(ifp->if_family);

    if (!if_family) {
	kprintf("Attempt to detach interface without family module - %s\n", 
	       ifp->if_name);
	splx(s);
	thread_funnel_set(network_flock, funnel_state);
	return ENODEV;
    }

    while (if_filter = TAILQ_FIRST(fhead)) 
	   dlil_detach_filter(if_filter->filter_id);

    ifp->refcnt--;

    if (ifp->refcnt == 0 && (ifp->if_eflags & IFEF_DETACH_DISABLED) == 0) {
	TAILQ_REMOVE(&ifnet, ifp, if_link);
	
	(*if_family->del_if)(ifp);

	if (--if_family->refcnt == 0) {
	    if (if_family->shutdown)
		(*if_family->shutdown)();
	    
	    TAILQ_REMOVE(&if_family_head, if_family, if_fam_next);
	    FREE(if_family, M_IFADDR);
	}

        dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_IF_DETACHED, 0, 0);
	splx(s);
	thread_funnel_set(network_flock, funnel_state);
	return 0;
    }
    else
    {
        dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_IF_DETACHING, 0, 0);
	splx(s);
	thread_funnel_set(network_flock, funnel_state);
	return DLIL_WAIT_FOR_FREE;
    }
}


int
dlil_reg_if_modules(u_long  interface_family, 
		    struct dlil_ifmod_reg_str  *ifmod)
{
    struct if_family_str *if_family;
    int s;
    boolean_t funnel_state;


    funnel_state = thread_funnel_set(network_flock, TRUE);
    s = splnet();
    if (find_family_module(interface_family))  {
	kprintf("Attempt to register dlil family module more than once - %d\n", 
	       interface_family);
	splx(s);
	thread_funnel_set(network_flock, funnel_state);
	return EEXIST;
    }

    if ((!ifmod->add_if) || (!ifmod->del_if) ||
	(!ifmod->add_proto) || (!ifmod->del_proto)) {
	kprintf("dlil_reg_if_modules passed at least one null pointer\n");
	splx(s);
	thread_funnel_set(network_flock, funnel_state);
	return EINVAL;
    }

    if_family = (struct if_family_str *) _MALLOC(sizeof(struct if_family_str), M_IFADDR, M_WAITOK);
    if (!if_family) {
	kprintf("dlil_reg_if_modules failed allocation\n");
	splx(s);
	thread_funnel_set(network_flock, funnel_state);
	return ENOMEM;
    }
    
    bzero(if_family, sizeof(struct if_family_str));

    if_family->if_family	= interface_family & 0xffff;
    if_family->shutdown		= ifmod->shutdown;
    if_family->add_if		= ifmod->add_if;
    if_family->del_if		= ifmod->del_if;
    if_family->add_proto	= ifmod->add_proto;
    if_family->del_proto	= ifmod->del_proto;
    if_family->ifmod_ioctl      = ifmod->ifmod_ioctl;
    if_family->refcnt		= 1;
    if_family->flags		= 0;

    TAILQ_INSERT_TAIL(&if_family_head, if_family, if_fam_next);
    splx(s);
    thread_funnel_set(network_flock, funnel_state);
    return 0;
}

int dlil_dereg_if_modules(u_long interface_family)
{
    struct if_family_str  *if_family;
    int s;
    boolean_t funnel_state;

    funnel_state = thread_funnel_set(network_flock, TRUE);
    s = splnet();
    if_family = find_family_module(interface_family);
    if (if_family == 0) {
	splx(s);
	thread_funnel_set(network_flock, funnel_state);
	return ENOENT;
    }

    if (--if_family->refcnt == 0) {
	if (if_family->shutdown)
	    (*if_family->shutdown)();
	
	TAILQ_REMOVE(&if_family_head, if_family, if_fam_next);
	FREE(if_family, M_IFADDR);
    }	
    else
	if_family->flags |= DLIL_SHUTDOWN;

    splx(s);
    thread_funnel_set(network_flock, funnel_state);
    return 0;
}
					    
	    



/*
 * Old if_attach no-op'ed function defined here for temporary backwards compatibility
 */

void if_attach(ifp)
    struct ifnet *ifp;
{
    dlil_if_attach(ifp);
}



int
dlil_inject_if_input(struct mbuf *m, char *frame_header, u_long from_id)
{
    struct ifnet		 *orig_ifp = 0;
    struct ifnet		 *ifp;
    struct if_proto		 *ifproto;
    struct if_proto		 *proto;
    struct dlil_filterq_entry	 *tmp;
    int				 retval = 0;
    struct dlil_filterq_head	 *fhead;
    int				 match_found;


    dlil_stats.inject_if_in1++;
    if (from_id > MAX_DLIL_FILTERS)
	return ERANGE;

    if (dlil_filters[from_id].type != DLIL_IF_FILTER)
	return ENOENT;

    ifp = dlil_filters[from_id].ifp;

/* 
 * Let interface filters (if any) do their thing ...
 */

    fhead = (struct dlil_filterq_head *) &ifp->if_flt_head;
    match_found = 0;

    if (TAILQ_EMPTY(fhead) == 0) {
	while (orig_ifp != ifp) {
	    orig_ifp = ifp;
	    TAILQ_FOREACH_REVERSE(tmp, fhead, que, dlil_filterq_head) {
		if ((match_found) && (IFILT(tmp).filter_if_input)) {
		    retval = (*IFILT(tmp).filter_if_input)(IFILT(tmp).cookie,
							   &ifp,
							   &m,
							   &frame_header);
		    if (retval) {
			if (retval == EJUSTRETURN)
			    return 0;
			else {
			    m_freem(m);
			    return retval;
			}
		    }
		    
		}
		
		if (ifp != orig_ifp)
		    break;
		
		if (from_id == tmp->filter_id)
		    match_found = 1;
	    }
	}
    }

    ifp->if_lastchange = time;

    /*
     * Call family demux module. If the demux module finds a match
     * for the frame it will fill-in the ifproto pointer.
     */
 
    retval = (*ifp->if_demux)(ifp, m, frame_header, &ifproto );

    if (m->m_flags & (M_BCAST|M_MCAST))
	ifp->if_imcasts++;
    
    if ((retval) && (ifp->offercnt)) {
	/*
	 * No match was found, look for any offers.
	 */
	struct dlil_proto_head	*tmp = (struct dlil_proto_head *) &ifp->proto_head;
	TAILQ_FOREACH(proto, tmp, next) {
	    if ((proto->dl_offer) && (proto->dl_offer(m, frame_header) == 0)) {
		ifproto = proto;
		retval = 0;
		break;
	    }
	}
    }

    if (retval) {
	if (retval != EJUSTRETURN) {
	    m_freem(m);
	    return retval;
	}
	else
	    return 0;
    } 
    else
	if (ifproto == 0) {
	    printf("ERROR - dlil_inject_if_input -- if_demux didn't return an if_proto pointer\n");
	    m_freem(m);
	    return 0;
	}
    
/*
 * Call any attached protocol filters.
 */
    TAILQ_FOREACH_REVERSE(tmp, &ifproto->pr_flt_head, que, dlil_filterq_head) { 
	if (PFILT(tmp).filter_dl_input) { 
	    retval = (*PFILT(tmp).filter_dl_input)(PFILT(tmp).cookie, 
						   &m,	
						   &frame_header,
						   &ifp);

	    if (retval) {
		if (retval == EJUSTRETURN)
		    return 0;
		else {
		    m_freem(m);
		    return retval;
		}
	    }
	} 
    }		  



    retval = (*ifproto->dl_input)(m, frame_header, 
				  ifp, ifproto->dl_tag, 
				  FALSE); 
    
    dlil_stats.inject_if_in2++;
    if (retval == EJUSTRETURN)
	retval = 0;
    else 
	if (retval)
	    m_freem(m);

    return retval;

}





int
dlil_inject_pr_input(struct mbuf *m, char *frame_header, u_long from_id)
{
    struct ifnet		 *orig_ifp = 0;
    struct dlil_filterq_entry	 *tmp;
    int				 retval;
    struct if_proto		 *ifproto = 0;
    int				 match_found;
    struct ifnet		 *ifp;
    

    dlil_stats.inject_pr_in1++;
    if (from_id > MAX_DLIL_FILTERS)
	return ERANGE;

    if (dlil_filters[from_id].type != DLIL_PR_FILTER)
	return ENOENT;

    ifproto = dlil_filters[from_id].proto;
    ifp	  = dlil_filters[from_id].ifp;


/*
 * Call any attached protocol filters.
 */

    match_found = 0;
    TAILQ_FOREACH_REVERSE(tmp, &ifproto->pr_flt_head, que, dlil_filterq_head) { 
	if ((match_found) && (PFILT(tmp).filter_dl_input)) { 
	    retval = (*PFILT(tmp).filter_dl_input)(PFILT(tmp).cookie, 
						   &m,	
						   &frame_header,
						   &ifp);

	    if (retval) {
		if (retval == EJUSTRETURN)
		    return 0;
		else {
		    m_freem(m);
		    return retval;
		}
	    }
	} 
	
	if (tmp->filter_id == from_id)
	    match_found = 1;
    }		  
    
    
    retval = (*ifproto->dl_input)(m, frame_header, 
				  ifp, ifproto->dl_tag, 
				  FALSE); 
    
    if (retval == EJUSTRETURN)
	retval = 0;
    else 
	if (retval)
	    m_freem(m);

    dlil_stats.inject_pr_in2++;
    return retval;
}



int
dlil_inject_pr_output(struct mbuf		*m,
		      struct sockaddr		*dest,
		      int			raw, 
		      char			*frame_type,
		      char			*dst_linkaddr,
		      u_long			from_id)
{
    struct ifnet		 *orig_ifp = 0;
    struct ifnet		 *ifp;
    struct dlil_filterq_entry	 *tmp;
    int				 retval = 0;
    char			 frame_type_buffer[MAX_FRAME_TYPE_SIZE * 4];
    char			 dst_linkaddr_buffer[MAX_LINKADDR * 4];
    struct dlil_filterq_head	 *fhead;
    int				 match_found;
    u_long			 dl_tag;


    dlil_stats.inject_pr_out1++;
    if (raw == 0) { 
	if (frame_type)
	    bcopy(frame_type, &frame_type_buffer[0], MAX_FRAME_TYPE_SIZE * 4);
	else
	    return EINVAL;

	if (dst_linkaddr)
	    bcopy(dst_linkaddr, &dst_linkaddr_buffer, MAX_LINKADDR * 4);
	else
	    return EINVAL;
    }

    if (from_id > MAX_DLIL_FILTERS)
	return ERANGE;

    if (dlil_filters[from_id].type != DLIL_PR_FILTER)
	return ENOENT;

    ifp	  = dlil_filters[from_id].ifp;
    dl_tag = dlil_filters[from_id].proto->dl_tag;
    

    frame_type	   = frame_type_buffer;
    dst_linkaddr   = dst_linkaddr_buffer;

    fhead = (struct dlil_filterq_head *) &ifp->if_flt_head;
    
/*
 * Run any attached protocol filters.
 */
    match_found = 0;

    if (TAILQ_EMPTY(dl_tag_array[dl_tag].pr_flt_head) == 0) {
	TAILQ_FOREACH(tmp, dl_tag_array[dl_tag].pr_flt_head, que) {
	    if ((match_found) && (PFILT(tmp).filter_dl_output)) {
		retval = (*PFILT(tmp).filter_dl_output)(PFILT(tmp).cookie, 
							 &m, &ifp, &dest, dst_linkaddr, frame_type);
		if (retval) {
		    if (retval == EJUSTRETURN)
			return 0;
		    else {
			m_freem(m);
			return retval;
		    }
		}
	    }

	    if (tmp->filter_id == from_id)
		match_found = 1;
	}
    }


/*
 * Call framing module 
 */
    if ((raw == 0) && (ifp->if_framer)) {
	retval = (*ifp->if_framer)(ifp, &m, dest, dst_linkaddr, frame_type);
	if (retval) {
	    if (retval == EJUSTRETURN)
		return 0;
	    else
	    {
		m_freem(m);
		return retval;
	    }
	}
    }
    

#if BRIDGE
    if (do_bridge) {
	struct mbuf *m0 = m ;
	
	if (m->m_pkthdr.rcvif)
	    m->m_pkthdr.rcvif = NULL ;
	ifp = bridge_dst_lookup(m);
	bdg_forward(&m0, ifp);
	if (m0)
	    m_freem(m0);

	return 0;
    }
#endif


/* 
 * Let interface filters (if any) do their thing ...
 */

    fhead = (struct dlil_filterq_head *) &ifp->if_flt_head;
    if (TAILQ_EMPTY(fhead) == 0) {
	while (orig_ifp != ifp) {
	    orig_ifp = ifp;
	    TAILQ_FOREACH(tmp, fhead, que) {
		if (IFILT(tmp).filter_if_output) {
		    retval = (*IFILT(tmp).filter_if_output)(IFILT(tmp).cookie,
							     &ifp,
							     &m);
		    if (retval) {
			if (retval == EJUSTRETURN)
			    return 0;
			else {
			    m_freem(m);
			    return retval;
			}
		    }

		}
		
		if (ifp != orig_ifp)
		    break;
	    }
	}
    }

/*
 * Finally, call the driver.
 */

    retval = (*ifp->if_output)(ifp, m);
    dlil_stats.inject_pr_out2++;
    if ((retval == 0) || (retval == EJUSTRETURN))
	return 0;
    else 
	return retval;
}


int
dlil_inject_if_output(struct mbuf *m, u_long from_id)
{
    struct ifnet		 *orig_ifp = 0;
    struct ifnet		 *ifp;
    struct dlil_filterq_entry	 *tmp;
    int				 retval = 0;
    struct dlil_filterq_head	 *fhead;
    int				 match_found;


    dlil_stats.inject_if_out1++;
    if (from_id > MAX_DLIL_FILTERS)
	return ERANGE;

    if (dlil_filters[from_id].type != DLIL_IF_FILTER)
	return ENOENT;

    ifp = dlil_filters[from_id].ifp;

/* 
 * Let interface filters (if any) do their thing ...
 */

    fhead = (struct dlil_filterq_head *) &ifp->if_flt_head;
    match_found = 0;

    if (TAILQ_EMPTY(fhead) == 0) {
	while (orig_ifp != ifp) {
	    orig_ifp = ifp;
	    TAILQ_FOREACH(tmp, fhead, que) {
		if ((match_found) && (IFILT(tmp).filter_if_output)) {
		    retval = (*IFILT(tmp).filter_if_output)(IFILT(tmp).cookie,
							     &ifp,
							     &m);
		    if (retval) {
			if (retval == EJUSTRETURN)
			    return 0;
			else {
			    m_freem(m);
			    return retval;
			}
		    }

		}
		
		if (ifp != orig_ifp)
		    break;

		if (from_id == tmp->filter_id)
		    match_found = 1;
	    }
	}
    }

/*
 * Finally, call the driver.
 */
    
    retval = (*ifp->if_output)(ifp, m);
    dlil_stats.inject_if_out2++;
    if ((retval == 0) || (retval == EJUSTRETURN))
	return 0;
    else 
	return retval;
}
