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
#include <sys/appleapiopts.h>

#if __STDC__

struct ifnet;
struct mbuf;
struct ether_header;

#endif


#ifdef __APPLE_API_UNSTABLE
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
    u_long	reserved[2];
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
    u_long	reserved[2];
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



#ifdef __APPLE_API_PRIVATE
struct dlil_filterq_entry {
    TAILQ_ENTRY(dlil_filterq_entry) que;
    u_long	 filter_id;
    int		 type;
    union {
	struct dlil_if_flt_str if_filter;
	struct dlil_pr_flt_str pr_filter;
    } variants;
};
#else
struct dlil_filterq_entry;
#endif /* __APPLE_API_PRIVATE */

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
    u_long			reserved[4];

};

#ifdef __APPLE_API_PRIVATE
TAILQ_HEAD(dlil_proto_head, if_proto);

struct dlil_tag_list_entry {
    TAILQ_ENTRY(dlil_tag_list_entry) next;
    struct ifnet		   *ifp;
    u_long			   dl_tag;
};
#endif /* __APPLE_API_PRIVATE */


#ifdef __APPLE_API_OBSOLETE
/* Obsolete types */
#define DLIL_DESC_RAW		1
#define DLIL_DESC_802_2		2
#define DLIL_DESC_802_2_SNAP	3
/*
 * DLIL_DESC_RAW - obsolete type, data in variants.bitmask or native_type
 *				   if variants.bitmask.proto_id_length, native_type in host
 *				   byte order.
 * DLIL_DESC_802_2 - obsolete, data in variants.desc_802_2
 * DLIL_DESC_802_2_SNAP - obsolete, data in variants.desc_802_2_SNAP
 *						  protocol field in host byte order
 */
#endif /* __APPLE_API_OBSOLETE */

/* Ehernet specific types */
#define DLIL_DESC_ETYPE2	4
#define DLIL_DESC_SAP		5
#define DLIL_DESC_SNAP		6
/*
 * DLIL_DESC_ETYPE2 - native_type must point to 2 byte ethernet raw protocol,
 *                    variants.native_type_length must be set to 2
 * DLIL_DESC_SAP - native_type must point to 3 byte SAP protocol
 *                 variants.native_type_length must be set to 3
 * DLIL_DESC_SNAP - native_type must point to 5 byte SNAP protocol
 *                  variants.native_type_length must be set to 5
 *
 * All protocols must be in Network byte order.
 *
 * Future interface families may define more protocol types they know about.
 * The type implies the offset and context of the protocol data at native_type.
 * The length of the protocol data specified at native_type must be set in
 * variants.native_type_length.
 */

struct dlil_demux_desc {
    TAILQ_ENTRY(dlil_demux_desc) next;
    
    int		type;
    u_char	*native_type;
    
    union {
        /* Structs in this union are obsolete. They exist for binary compatability only */
        /* Only the native_type_length is used */
        struct {
            u_long   proto_id_length; /* IN LONGWORDS!!! */
            u_char   *proto_id;		  /* No longer supported by Ethernet family */
            u_char   *proto_id_mask;
        } bitmask;
        
        struct {
            u_char   dsap;
            u_char   ssap;
            u_char   control_code;
            u_char   pad;
        } desc_802_2;
        
        struct {
            u_char   dsap;			/* Ignored, assumed to be 0xAA */
            u_char   ssap;			/* Ignored, assumed to be 0xAA */
            u_char   control_code; 	/* Ignored, assumed to be 0x03 */
            u_char   org[3];
            u_short  protocol_type; /* In host byte order */
        } desc_802_2_SNAP;
        
        /* Length of data pointed to by native_type, must be set correctly */
        u_int32_t	native_type_length;
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
    dl_pre_output_func	pre_output;
    dl_event_func		event;
    dl_offer_func		offer;
    dl_ioctl_func		ioctl;
    u_long			reserved[4];
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
    int (*init_if)(struct ifnet *ifp);
    u_long	reserved[3];
};


int dlil_reg_if_modules(u_long  interface_family,
			struct dlil_ifmod_reg_str  *ifmod_reg);

struct dlil_protomod_reg_str {
    /* 
     *   attach the protocol to the interface and return the dl_tag 
     */
    int (*attach_proto)(struct ifnet *ifp, u_long *dl_tag);

    /*
     *   detach the protocol from the interface. 
     *   this is optionnal. If it is NULL, DLIL will use 0 default detach function.
     */
    int (*detach_proto)(struct ifnet *ifp, u_long dl_tag); 

    /*
     *   reserved for future use. MUST be NULL.
     */
    u_long	reserved[4];
};

/* 

Function : dlil_reg_proto_module

    A DLIL protocol module is a piece of code that know how to handle a certain type
    of protocol (PF_INET, PF_INET6, ...) for a certain family of interface (APPLE_IF_FAM_ETHERNET, 
    APPLE_IF_FAM_PPP, ...).
    
    dlil_reg_proto_module() allows the registration of such a protocol/interface handler before any 
    interface is attached.
    Typically, the attach and detach function of the protocol handler will call 
    dlil_{attach/detach}_protocol with the parameter specific to the protocol.
    
    The goal of this modules is to insulate the actual protocol (IP, IPv6) from the DLIL details.

Parameters :
    'protocol_family' is PF_INET, PF_INET6, ...
    'interface_family' is APPLE_IF_FAM_ETHERNET, APPLE_IF_FAM_PPP, ...
    'protomod_reg' is the protocol registration structure.
            'attach_proto' funtion is mandatory.
            'detach_proto' funtion is optional (DLIL will manage it).

Return code :    

0 :

    No error.

ENOMEM:

    No memory can be allocated for internal data structure.

EEXIST:

    The protocol family has already been registered for this interface family.

EINVAL:

    The dlil_protomod_reg_str structure contains incorrect values.

*/

int dlil_reg_proto_module(u_long protocol_family, u_long interface_family,
			struct dlil_protomod_reg_str  *protomod_reg);

/* 

Function : dlil_dereg_proto_module

    dlil_dereg_proto_module() will unregister the protocol module previously 
    registered with dlil_dereg_proto_module().
    
    There is no restriction when to call it. 
    Interfaces or protoco can be attached, it will not prevent the deregistration of the module.
    
Parameters :
    'protocol_family' is PF_INET, PF_INET6, ...
    'interface_family' is APPLE_IF_FAM_ETHERNET, APPLE_IF_FAM_PPP, ...

Return code :    

0 :

    No error.

ENOENT:

    No module was registered..

*/

int dlil_dereg_proto_module(u_long protocol_family, u_long interface_family);

/* 

Function : dlil_plumb_protocol

    dlil_plumb_protocol() will plumb a protocol to an actual interface.
    This will find a registered protocol module and call its attach function.
    The module will typically call dlil_attach_protocol with the appropriate parameters,
    and will return the dl_tag of the attachement.
    It is up to the caller to handle the dl_tag. 
    Some protocol (IPv4) will stick it in their internal structure for future use.
    Some other protocol (IPv6) can ignore the dl_tag.
        
Parameters :
    'protocol_family' is PF_INET, PF_INET6, ...
    'ifp' is the interface to plumb the protocol to.
    'dl_tag' is the tag returned from the succesful attachement.
    
Return code :    

0 :

    No error.

ENOENT:

    No module was registered.

other: 
    
    Error returned by the attach_proto function

*/
int dlil_plumb_protocol(u_long protocol_family, struct ifnet *ifp, u_long *dl_tag);

/* 

Function : dlil_unplumb_protocol

    dlil_unplumb_protocol() will unplumb a protocol from an interface.
    This will find a registered protocol module and call its detach function.
    The module will typically call dlil_detach_protocol with the appropriate parameters.
    If no module is found, this function will call dlil_detach_protocol directly. 
    
Parameters :
    'protocol_family' is PF_INET, PF_INET6, ...
    'ifp' is APPLE_IF_FAM_ETHERNET, APPLE_IF_FAM_PPP, ...
    
Return code :    

0 :

    No error.

ENOENT:

    No module was registered.

other: 
    
    Error returned by the attach_proto function

*/
int dlil_unplumb_protocol(u_long protocol_family, struct ifnet *ifp);

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


/* 

Function : dlil_if_acquire

    DLIL manages the list of ifnet interfaces allocated using the dlil_if_acquire
    function. This list if not the same as the list of attached interfaces, 
    visible with ifconfig.
    This list contains attached as well as detached interfaces.
	Detached interfaces are kept in the list to prevent the kernel from crashing
	by using an old ifp.

    if it succeeds, dlil_if_acquire returns an ifnet data structure.
    This ifnet can either be a new allocated block of memory, or an ifnet
    that already existed and that DLIL has found in its list of unused
    interface and that matches the family/uniqueid tuple.

    dlil_if_acquire can fail if the requested interface is already in use, 
    or if no memory is available to create a new interface.

    The typical sequence of call for a driver will be :
    dlil_if_acquire(... &ifp)
    ... Fill in the ifnet ...
    dlil_if_attach(ifp)
    ... Driver work ...
    dlil_if_detach(ifp)
    dlil_if_release(ifp)

    Important : ifnet allocated by DLIL are managed by DLIL. DLIL takes care
    of them, and keeps them until a driver wants to reuse them, but DLIL may
    also decide to free them when not in use by a driver.

    Note : the structure returned will actually be large enough to contain
    an arpcom structure (ifnet + ethernet) structure.
    Drivers cannot extend the structure and must to store their private 
    information in if_sofc and if_private.

Parameters :
    'family' uniquely identifies DLIL interface family.
    'uniqueid' is a unique identifier for that interface, managed by the
        driver (for example MAC address for ethernet).
    'uniqueid_len' is the length of the unique id.
    'ifp' contains on output the allocated ifnet.

Return code :    

0 :

    If an ifnet matching the uniqueid is found, the matching ifnet is returned
    in ifp and the flags IFEF_REUSE and IF_INUSE are set in the if_eflags.
    The fields in the ifnet are NOT zeroed and may contain old values that
    the driver can reuse. [They are not necessarily the values that were
    there when the driver released the ifnet, as protocol might have
    continued to update them].

    If no matching ifnet is found, a new structure is allocated and returned
    in ifp with all fields initialized to 0.
    The flag IF_INUSE is set in the if_eflags. IFEF_REUSE is NOT set.
    dlil_if_acquire will copy the uniqueid and keep it for matching purpose.

    If 'uniqueid' is NULL, then dlil_if_acquire will return the first
    ifnet that contains a null uniqueid for that family, with the flags
    IFEF_REUSE and IF_INUSE set.
    If no ifnet is available, a new one will be created.

ENOMEM:

    If no matching interface is found, and no memory can be allocated,
    dlil_if_acquire will return ENOMEM.


EBUSY:

    If the unique id matches the id of an interface currently in use,
    dlil_if_acquire will return EBUSY.
    An interface 'in use' is an allocated interface, not necessarily attached.

*/

int dlil_if_acquire(u_long family, void *uniqueid, size_t uniqueid_len, 
			struct ifnet **ifp);
			

/* 

Function : dlil_if_release

	dlil_if_release will transfer control of the ifnet to DLIL.
	DLIL will keep the interface in its list, marking it unused.
	The fields will be left in their current state, so the driver can reuse
	the ifnet later, by calling dlil_if_acquire.
	The if_eflags IF_INUSE will be cleared.
	The fields if_output, if_ioctl, if_free and if_set_bpf_tap will be changed 
	to point to DLIL private functions.
	After calling dlil_if_acquire, the driver can safely terminate and
	unload if necessary.
	Note : if the call to dlil_if_detach returns DLIL_WAIT_FOR_FREE, the
	driver can safely ignore it and call dlil_if_release.

Parameters :
	ifp is the pointer to the ifnet to release.

*/

void dlil_if_release(struct ifnet *ifp);

#endif /* __APPLE_API_UNSTABLE */
#endif /* DLIL_H */
