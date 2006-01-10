/*
 * Copyright (c) 1999-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

/*
 * Support for socket filter kernel extensions
 */

#ifndef NET_KEXT_NET_H
#define NET_KEXT_NET_H

#include <sys/appleapiopts.h>

#include <sys/queue.h>
#include <sys/cdefs.h>

#ifdef BSD_KERNEL_PRIVATE

#include <sys/kpi_socketfilter.h>

/*
 * Internal implementation bits
 */

struct socket_filter;

#define	SFEF_DETACHUSEZERO	0x1	// Detach when use reaches zero
#define	SFEF_UNREGISTERING	0x2	// Remove due to unregister

struct socket_filter_entry {
	struct socket_filter_entry	*sfe_next_onsocket;
	struct socket_filter_entry	*sfe_next_onfilter;
	
	struct socket_filter		*sfe_filter;
	struct socket				*sfe_socket;
	void						*sfe_cookie;
	
	u_int32_t					sfe_flags;
};

#define	SFF_DETACHING		0x1

struct socket_filter {
	TAILQ_ENTRY(socket_filter)	sf_protosw_next;	
	TAILQ_ENTRY(socket_filter)	sf_global_next;
	struct socket_filter_entry	*sf_entry_head;
	
	struct protosw				*sf_proto;
	struct sflt_filter			sf_filter;
	u_int32_t					sf_flags;
	u_int32_t					sf_usecount;
};

TAILQ_HEAD(socket_filter_list, socket_filter);

/* Private, internal implementation functions */
void	sflt_init(void);
void	sflt_initsock(struct socket *so);
void	sflt_termsock(struct socket *so);
void	sflt_use(struct socket *so);
void	sflt_unuse(struct socket *so);
void	sflt_notify(struct socket *so, sflt_event_t event, void *param);
int		sflt_data_in(struct socket *so, const struct sockaddr *from, mbuf_t *data,
					 mbuf_t *control, sflt_data_flag_t flags, int *filtered);
int		sflt_attach_private(struct socket *so, struct socket_filter *filter, sflt_handle handle, int locked);

#endif /* BSD_KERNEL_PRIVATE */

#define NFF_BEFORE		0x01
#define NFF_AFTER		0x02

#define NKE_OK 0
#define NKE_REMOVE -1

/*
 * Interface structure for inserting an installed socket NKE into an
 *  existing socket.
 * 'handle' is the NKE to be inserted, 'where' is an insertion point,
 *  and flags dictate the position of the to-be-inserted NKE relative to
 *  the 'where' NKE.  If the latter is NULL, the flags indicate "first"
 *  or "last"
 */
#if __DARWIN_ALIGN_POWER
#pragma options align=power
#endif

struct so_nke
{	unsigned int nke_handle;
	unsigned int nke_where;
	int nke_flags; /* NFF_BEFORE, NFF_AFTER: net/kext_net.h */
	unsigned long reserved[4];	/* for future use */
};

#if __DARWIN_ALIGN_POWER
#pragma options align=reset
#endif

#endif /* NET_KEXT_NET_H */

