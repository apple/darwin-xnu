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


#ifndef SYS_KERN_EVENT_H
#define SYS_KERN_EVENT_H

#include <sys/appleapiopts.h>
#include <sys/ioccom.h>
#include <sys/sys_domain.h>

#define KEVENTS_ON  1
#define KEV_SNDSPACE (4 * 1024)
#define KEV_RECVSPACE (8 * 1024)

#define KEV_ANY_VENDOR    0
#define KEV_ANY_CLASS     0
#define KEV_ANY_SUBCLASS  0

/*
 * Vendor Code
 */

#define KEV_VENDOR_APPLE	1


/*
 * Definition of top-level classifications
 */

#define KEV_NETWORK_CLASS 1
#define KEV_IOKIT_CLASS   2
#define KEV_SYSTEM_CLASS  3


struct kern_event_msg {
     u_long	       total_size;      /* Size of entire event msg */
     u_long	       vendor_code;     /* For non-Apple extensibility */
     u_long	       kev_class;	/* Layer of event source */
     u_long	       kev_subclass;    /* Component within layer    */
     u_long	       id;	        /* Monotonically increasing value  */
     u_long            event_code;      /* unique code */
     u_long            event_data[1];   /* One or more data longwords      */

};

#define KEV_MSG_HEADER_SIZE   (6 * sizeof(u_long))


struct kev_request {
     u_long	vendor_code;
     u_long	kev_class;
     u_long	kev_subclass;
};

#define SIOCGKEVID	_IOR('e', 1, u_long)
#define SIOCSKEVFILT	_IOW('e', 2, struct kev_request)
#define SIOCGKEVFILT    _IOR('e', 3, struct kev_request)

#ifdef KERNEL
#ifdef __APPLE_API_UNSTABLE

#define N_KEV_VECTORS     5

struct kev_d_vectors {

     u_long	data_length;	/* Length of the event data */
     void	*data_ptr;    /* Pointer to event data */
};     


struct kev_msg {
     u_long	       vendor_code;     /* For non-Apple extensibility */
     u_long	       kev_class;	/* Layer of event source */
     u_long	       kev_subclass;    /* Component within layer    */
     u_long	       event_code;      /* The event code        */
     struct kev_d_vectors  dv[N_KEV_VECTORS];      /* Up to n data vectors  */
};

int  kev_post_msg(struct kev_msg *event);

#endif /* ___APPLE_API_UNSTABLE */
#ifdef __APPLE_API_PRIVATE

LIST_HEAD(kern_event_head, kern_event_pcb);

struct  kern_event_pcb {
     LIST_ENTRY(kern_event_pcb) ev_link;     /* glue on list of all PCBs */
     struct  socket *ev_socket;     /* pointer back to socket */
     u_long	    vendor_code_filter;
     u_long	    class_filter;
     u_long	    subclass_filter;
};

#define sotoevpcb(so)   ((struct kern_event_pcb *)((so)->so_pcb))

#endif /* __APPLE_API_PRIVATE */
#endif

#endif
