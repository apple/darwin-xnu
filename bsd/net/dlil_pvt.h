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
#ifndef DLIL_PVT_H
#define DLIL_PVT_H

#include <net/dlil.h>
#include <sys/queue.h>

struct dlil_if_filterq_entry {
    TAILQ_ENTRY(dlil_if_filterq_entry) que;
    struct dlil_interface_filter_str if_filter;
};


struct dlil_family_mod_str {
    TAILQ_ENTRY(dlil_family_mod_str)	dl_fam_next;
    char	*interface_family;
    int (*add_if)(struct ifnet_ptr  *ifp);
    int (*del_if)(struct ifnet    *ifp);
    int (*add_proto)(TAILQ_HEAD(ddesc_head_name, dlil_demux_desc) demux_desc_head,
		     struct if_proto  *proto);
    int (*del_proto)(struct if_proto  *proto);
}


    
#endif
