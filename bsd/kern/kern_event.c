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
 *
 */
/*
 *	@(#)kern_event.c       1.0 (3/31/2000)
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/mbuf.h>
#include <sys/kern_event.h>
#include <sys/malloc.h>


extern struct domain systemdomain;



int	raw_usrreq();
struct pr_usrreqs event_usrreqs;

struct protosw eventsw[] = {
     {
	  SOCK_RAW,	        &systemdomain,	SYSPROTO_EVENT,		PR_ATOMIC,
	  0,		0,		0,		0,
	  0,
	  0,		0,		0,		0,
	  0,		&event_usrreqs
     }
};

static
struct kern_event_head kern_event_head;

static u_long static_event_id = 0;

int kev_attach(struct socket *so, int proto, struct proc *p)
{
     int error;
     struct kern_event_pcb  *ev_pcb;

     ev_pcb = _MALLOC(sizeof(struct kern_event_pcb), M_PCB, M_WAITOK);
     if (ev_pcb == 0)
	  return ENOBUFS;

     ev_pcb->ev_socket = so;
     ev_pcb->vendor_code_filter = 0xffffffff;

     so->so_pcb = (caddr_t) ev_pcb;
     LIST_INSERT_HEAD(&kern_event_head, ev_pcb, ev_link);
     error = soreserve(so, KEV_SNDSPACE, KEV_RECVSPACE);
     if (error)
	  return error;

     return 0;
}


int kev_detach(struct socket *so)
{
     struct kern_event_pcb *ev_pcb = (struct kern_event_pcb *) so->so_pcb;

     LIST_REMOVE(ev_pcb, ev_link);
     if (ev_pcb)
	  FREE(ev_pcb, M_PCB);

     return 0;
}


int  kev_post_msg(struct kev_msg *event_msg)
{
     struct mbuf *m, *m2;
     struct kern_event_pcb  *ev_pcb;
     struct kern_event_msg  *ev;
     char              *tmp;
     int               total_size;
     int               i;


     m = m_get(M_DONTWAIT, MT_DATA);
     if (m == 0)
	  return ENOBUFS;

     ev = mtod(m, struct kern_event_msg *);
     total_size = KEV_MSG_HEADER_SIZE;

     tmp = (char *) &ev->event_data[0];
     for (i = 0; i < 5; i++) {
	  if (event_msg->dv[i].data_length == 0)
	       break;

	  total_size += event_msg->dv[i].data_length;
	  bcopy(event_msg->dv[i].data_ptr, tmp, 
		event_msg->dv[i].data_length);
	  tmp += event_msg->dv[i].data_length;
     }


     ev->id = ++static_event_id;
     ev->total_size   = total_size;
     ev->vendor_code  = event_msg->vendor_code;
     ev->kev_class    = event_msg->kev_class;
     ev->kev_subclass = event_msg->kev_subclass;
     ev->event_code   = event_msg->event_code;

     m->m_len = total_size;
     ev_pcb = LIST_FIRST(&kern_event_head);
     for (ev_pcb = LIST_FIRST(&kern_event_head); 
	  ev_pcb; 
	  ev_pcb = LIST_NEXT(ev_pcb, ev_link)) {

	  if (ev_pcb->vendor_code_filter != KEV_ANY_VENDOR) {
	       if (ev_pcb->vendor_code_filter != ev->vendor_code)
		    continue;

	       if (ev_pcb->class_filter != KEV_ANY_CLASS) {
		    if (ev_pcb->class_filter != ev->kev_class)
			 continue;

		    if ((ev_pcb->subclass_filter != KEV_ANY_SUBCLASS) &&
			(ev_pcb->subclass_filter != ev->kev_subclass))
			 continue;
	       }
	  }

	  m2 = m_copym(m, 0, m->m_len, M_NOWAIT);
	  if (m2 == 0) {
	       m_free(m);
	       return ENOBUFS;
	  }

	  sbappendrecord(&ev_pcb->ev_socket->so_rcv, m2);
	  sorwakeup(ev_pcb->ev_socket);
     }


     m_free(m);
     return 0;
}


int kev_control(so, cmd, data, ifp, p)
    struct socket *so;
    u_long cmd;
    caddr_t data;
    register struct ifnet *ifp;
    struct proc *p;
{
     struct kev_request *kev_req = (struct kev_request *) data;
     int  stat = 0;
     struct kern_event_pcb  *ev_pcb;
     u_long  *id_value = (u_long *) data;


     switch (cmd) {

     case SIOCGKEVID:
	  *id_value = static_event_id;
	  break;

     case SIOCSKEVFILT:
	  ev_pcb = (struct kern_event_pcb *) so->so_pcb;
	  ev_pcb->vendor_code_filter = kev_req->vendor_code;
	  ev_pcb->class_filter     = kev_req->kev_class;
	  ev_pcb->subclass_filter  = kev_req->kev_subclass;
	  break;

     case SIOCGKEVFILT:
	  ev_pcb = (struct kern_event_pcb *) so->so_pcb;
	  kev_req->vendor_code = ev_pcb->vendor_code_filter;
	  kev_req->kev_class   = ev_pcb->class_filter;
	  kev_req->kev_subclass = ev_pcb->subclass_filter;
	  break;

     default:
	  return EOPNOTSUPP;
     }

     return 0;
}


struct pr_usrreqs event_usrreqs = {
     pru_abort_notsupp, pru_accept_notsupp, kev_attach, pru_bind_notsupp, pru_connect_notsupp,
     pru_connect2_notsupp, kev_control, kev_detach, pru_disconnect_notsupp,
     pru_listen_notsupp, pru_peeraddr_notsupp, pru_rcvd_notsupp, pru_rcvoob_notsupp,
     pru_send_notsupp, pru_sense_null, pru_shutdown_notsupp, pru_sockaddr_notsupp,
     pru_sosend_notsupp, soreceive, sopoll
};



