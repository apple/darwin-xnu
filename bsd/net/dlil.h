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


#ifndef DLIL_H
#define DLIL_H

#if __STDC__

struct ifnet;
struct mbuf;
struct ether_header;

#endif



#define DLIL_LAST_FILTER   -1
#define DLIL_NULL_FILTER   -2

#define DLIL_WAIT_FOR_FREE -2

#define DLIL_BLUEBOX 1



#include <net/if.h>
#include <net/if_var.h>
#include <sys/kern_event.h>

enum {
	BPF_TAP_DISABLE,
	BPF_TAP_INPUT,
	BPF_TAP_OUTPUT,
	BPF_TAP_INPUT_OUTPUT
};


struct dl_tag_attr_str {
    u_long	dl_tag;
    short	if_flags;
    short	if_unit;
    u_long	if_family;
    u_long	protocol_family;
};


struct dlil_pr_flt_str {
    caddr_t	 cookie;

    int	(*filter_dl_input)(caddr_t	cookie, 
			   struct mbuf	**m, 
			   char		**frame_header, 
			   struct ifnet **ifp);


    int (*filter_dl_output)(caddr_t	    cookie, 
			    struct mbuf	    **m, 
			    struct ifnet    **ifp, 
			    struct sockaddr **dest,
			    char            *dest_linkaddr, 
			    char	    *frame_type);

    int (*filter_dl_event)(caddr_t	      cookie, 
			   struct kern_event_msg   *event_msg);

    int (*filter_dl_ioctl)(caddr_t	cookie, 
			   struct ifnet *ifp,
			   u_long	ioctl_cmd,
			   caddr_t	ioctl_arg);

    int	(*filter_detach)(caddr_t  cookie);
};

struct dlil_if_flt_str {
    caddr_t				   cookie;
    int	(*filter_if_input)(caddr_t         cookie,
			   struct ifnet    **ifnet_ptr,
			   struct mbuf     **mbuf_ptr,
			   char		   **frame_ptr);

    int	(*filter_if_event)(caddr_t          cookie,
			   struct ifnet     **ifnet_ptr,
			   struct kern_event_msg **event_msg_ptr);

    int	(*filter_if_output)(caddr_t      cookie,
			    struct ifnet **ifnet_ptr,
			    struct mbuf  **mbuf_ptr);


    int	(*filter_if_ioctl)(caddr_t       cookie,
			   struct ifnet  *ifnet_ptr,
			   u_long	 ioctl_code_ptr,
			   caddr_t       ioctl_arg_ptr);

    int	(*filter_if_free)(caddr_t      cookie,
			  struct ifnet *ifnet_ptr);

    int	(*filter_detach)(caddr_t  cookie);
};


#define DLIL_PR_FILTER  1
#define DLIL_IF_FILTER  2



typedef int (*dl_input_func)(struct mbuf *m, char *frame_header,
			     struct ifnet *ifp, u_long  dl_tag, int sync_ok);
typedef int (*dl_pre_output_func)(struct ifnet		*ifp,
				  struct mbuf		**m,
				  struct sockaddr	*dest,
				  caddr_t		route_entry,
				  char			*frame_type,
				  char			*dst_addr,
				  u_long		dl_tag);

typedef int (*dl_event_func)(struct kern_event_msg  *event,
			     u_long            dl_tag);

typedef int (*dl_offer_func)(struct mbuf *m, char *frame_header);
typedef int (*dl_ioctl_func)(u_long	dl_tag,
			     struct ifnet *ifp,
			     u_long	ioctl_cmd,
			     caddr_t	ioctl_arg);



struct dlil_filterq_entry {
    TAILQ_ENTRY(dlil_filterq_entry) que;
    u_long	 filter_id;
    int		 type;
    union {
	struct dlil_if_flt_str if_filter;
	struct dlil_pr_flt_str pr_filter;
    } variants;
};


TAILQ_HEAD(dlil_filterq_head, dlil_filterq_entry);


struct if_proto {
    TAILQ_ENTRY(if_proto)			next;
    u_long					dl_tag;
    struct dlil_filterq_head                    pr_flt_head;
    struct ifnet		*ifp;
    dl_input_func		dl_input;
    dl_pre_output_func		dl_pre_output;
    dl_event_func		dl_event;
    dl_offer_func		dl_offer;
    dl_ioctl_func		dl_ioctl;
    u_long			protocol_family;

};

TAILQ_HEAD(dlil_proto_head, if_proto);

struct dlil_tag_list_entry {
    TAILQ_ENTRY(dlil_tag_list_entry) next;
    struct ifnet		   *ifp;
    u_long			   dl_tag;
};


#define DLIL_DESC_RAW		1
#define DLIL_DESC_802_2		2
#define DLIL_DESC_802_2_SNAP	3

struct dlil_demux_desc {
    TAILQ_ENTRY(dlil_demux_desc) next;
    int				 type;

    u_char  *native_type;
    union {
	struct {
	    u_long   proto_id_length; /* IN LONGWORDS!!! */
	    u_char   *proto_id;
	    u_char   *proto_id_mask;

	} bitmask;

	struct {
	    u_char   dsap;
	    u_char   ssap;
	    u_char   control_code;
	    u_char   pad;
	} desc_802_2;

	struct {
	    u_char   dsap;
	    u_char   ssap;
	    u_char   control_code;
	    u_char   org[3];
	    u_short  protocol_type;
	} desc_802_2_SNAP;
    } variants;
};

TAILQ_HEAD(ddesc_head_str, dlil_demux_desc);


struct dlil_proto_reg_str {
    struct ddesc_head_str	demux_desc_head;
    u_long			interface_family;
    u_long			protocol_family;
    short			unit_number;
    int				default_proto; /* 0 or 1 */
    dl_input_func		input;
    dl_pre_output_func		pre_output;
    dl_event_func		event;
    dl_offer_func		offer;
    dl_ioctl_func		ioctl;
};


int dlil_attach_interface_filter(struct ifnet		   *ifnet_ptr,
				 struct dlil_if_flt_str    *interface_filter,
				 u_long			   *filter_id,
				 int			   insertion_point);

int
dlil_input(struct ifnet  *ifp, struct mbuf *m_head, struct mbuf *m_tail);

int
dlil_output(u_long		dl_tag,
	    struct mbuf		*m,
	    caddr_t		route,
	    struct sockaddr     *dest,
	    int			raw);


int
dlil_ioctl(u_long	proto_family,
	   struct ifnet	*ifp,
	   u_long	ioctl_code,
	   caddr_t	ioctl_arg);

int
dlil_attach_protocol(struct dlil_proto_reg_str   *proto,
		     u_long		         *dl_tag);

int
dlil_detach_protocol(u_long	dl_tag);

int
dlil_if_attach(struct ifnet	*ifp);

int
dlil_attach_protocol_filter(u_long	            dl_tag,
			    struct dlil_pr_flt_str  *proto_filter,
			    u_long   	            *filter_id,
			    int		            insertion_point);
int
dlil_detach_filter(u_long	filter_id);

struct dlil_ifmod_reg_str {
    int (*add_if)(struct ifnet *ifp);
    int (*del_if)(struct ifnet *ifp);
    int (*add_proto)(struct ddesc_head_str   *demux_desc_head,
		     struct if_proto  *proto, u_long dl_tag);
    int (*del_proto)(struct if_proto  *proto, u_long dl_tag);
    int (*ifmod_ioctl)(struct ifnet *ifp, u_long ioctl_cmd, caddr_t data);
    int	(*shutdown)();
};


int dlil_reg_if_modules(u_long  interface_family,
			struct dlil_ifmod_reg_str  *ifmod_reg);

int 
dlil_inject_if_input(struct mbuf *m, char *frame_header, u_long from_id);

int
dlil_inject_pr_input(struct mbuf *m, char *frame_header, u_long from_id);

int
dlil_inject_pr_output(struct mbuf		*m,
		      struct sockaddr		*dest,
		      int			raw, 
		      char			*frame_type,
		      char			*dst_linkaddr,
		      u_long			from_id);

int
dlil_inject_if_output(struct mbuf *m, u_long from_id);

int  
dlil_find_dltag(u_long if_family, short unit, u_long proto_family, u_long *dl_tag);


int
dlil_event(struct ifnet *ifp, struct kern_event_msg *event);

int dlil_dereg_if_modules(u_long interface_family);

int
dlil_if_detach(struct ifnet *ifp);

#endif /* DLIL_H */
