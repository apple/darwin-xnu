/*
 * Copyright (c) 2003-2007 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <sys/kpi_socketfilter.h>

#include <sys/socket.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/protosw.h>
#include <kern/locks.h>
#include <net/kext_net.h>

#include <libkern/libkern.h>

#include <string.h>

static struct socket_filter_list	sock_filter_head;
static lck_mtx_t					*sock_filter_lock = 0;

static void	sflt_detach_private(struct socket_filter_entry *entry, int unregistering);

__private_extern__ void
sflt_init(void)
{
	lck_grp_attr_t	*grp_attrib = 0;
	lck_attr_t		*lck_attrib = 0;
	lck_grp_t		*lck_group = 0;
	
	TAILQ_INIT(&sock_filter_head);
	
	/* Allocate a spin lock */
	grp_attrib = lck_grp_attr_alloc_init();
	lck_group = lck_grp_alloc_init("socket filter lock", grp_attrib);
	lck_grp_attr_free(grp_attrib);
	lck_attrib = lck_attr_alloc_init();
	sock_filter_lock = lck_mtx_alloc_init(lck_group, lck_attrib);
	lck_grp_free(lck_group);
	lck_attr_free(lck_attrib);
}

__private_extern__ void
sflt_initsock(
	struct socket *so)
{
	struct protosw *proto = so->so_proto;
	struct socket_filter *filter;
	
	if (TAILQ_FIRST(&proto->pr_filter_head) != NULL) {
		lck_mtx_lock(sock_filter_lock);
		TAILQ_FOREACH(filter, &proto->pr_filter_head, sf_protosw_next) {
			sflt_attach_private(so, filter, 0, 0);
		}
		lck_mtx_unlock(sock_filter_lock);
	}
}

__private_extern__ void
sflt_termsock(
	struct socket *so)
{
	struct socket_filter_entry *filter;
	struct socket_filter_entry *filter_next;
	
	for (filter = so->so_filt; filter; filter = filter_next) {
		filter_next = filter->sfe_next_onsocket;
		sflt_detach_private(filter, 0);
	}
	so->so_filt = NULL;
}

__private_extern__ void
sflt_use(
	struct socket *so)
{
	so->so_filteruse++;
}

__private_extern__ void
sflt_unuse(
	struct socket *so)
{
	so->so_filteruse--;
	if (so->so_filteruse == 0) {
		struct socket_filter_entry *filter;
		struct socket_filter_entry *next_filter;
		// search for detaching filters
		for (filter = so->so_filt; filter; filter = next_filter) {
			next_filter = filter->sfe_next_onsocket;
			
			if (filter->sfe_flags & SFEF_DETACHUSEZERO) {
				sflt_detach_private(filter, 0);
			}
		}
	}
}

__private_extern__ void
sflt_notify(
	struct socket	*so,
	sflt_event_t	event,
	void			*param)
{
	struct socket_filter_entry	*filter;
	int						 	filtered = 0;
	
	for (filter = so->so_filt; filter;
		 filter = filter->sfe_next_onsocket) {
		if (filter->sfe_filter->sf_filter.sf_notify) {
			if (filtered == 0) {
				filtered = 1;
				sflt_use(so);
				socket_unlock(so, 0);
			}
			filter->sfe_filter->sf_filter.sf_notify(
				filter->sfe_cookie, so, event, param);
		}
	}
	
	if (filtered != 0) {
		socket_lock(so, 0);
		sflt_unuse(so);
	}
}

__private_extern__ int
sflt_data_in(
	struct socket			*so,
	const struct sockaddr	*from,
	mbuf_t					*data,
	mbuf_t					*control,
	sflt_data_flag_t		flags,
	int						*filtered)
{
	struct socket_filter_entry	*filter;
	int							error = 0;
	int							filtered_storage;
	
	if (filtered == NULL)
		filtered = &filtered_storage;
	*filtered = 0;
	
	for (filter = so->so_filt; filter && (error == 0);
		 filter = filter->sfe_next_onsocket) {
		if (filter->sfe_filter->sf_filter.sf_data_in) {
			if (*filtered == 0) {
				*filtered = 1;
				sflt_use(so);
				socket_unlock(so, 0);
			}
			error = filter->sfe_filter->sf_filter.sf_data_in(
						filter->sfe_cookie, so, from, data, control, flags);
		}
	}
	
	if (*filtered != 0) {
		socket_lock(so, 0);
		sflt_unuse(so);
	}
	
	return error;
}

/* sflt_attach_private
 *
 * Assumptions: If filter is not NULL, socket_filter_lock is held.
 */

__private_extern__ int
sflt_attach_private(
	struct socket *so,
	struct socket_filter *filter,
	sflt_handle			handle,
	int sock_locked)
{
	struct socket_filter_entry *entry = NULL;
	int didlock = 0;
	int error = 0;
	
	if (filter == NULL) {
		/* Find the filter by the handle */
		lck_mtx_lock(sock_filter_lock);
		didlock = 1;
		
		TAILQ_FOREACH(filter, &sock_filter_head, sf_global_next) {
			if (filter->sf_filter.sf_handle == handle)
				break;
		}
	}
	
	if (filter == NULL)
		error = ENOENT;
	
	if (error == 0) {
		/* allocate the socket filter entry */
		MALLOC(entry, struct socket_filter_entry *, sizeof(*entry), M_IFADDR, M_WAITOK);
		if (entry == NULL) {
			error = ENOMEM;
		}
	}
	
	if (error == 0) {
		/* Initialize the socket filter entry and call the attach function */
		entry->sfe_filter = filter;
		entry->sfe_socket = so;
		entry->sfe_cookie = NULL;
		entry->sfe_flags = 0;
		if (entry->sfe_filter->sf_filter.sf_attach) {
			filter->sf_usecount++;
		
			if (sock_locked)
				socket_unlock(so, 0);	
			error = entry->sfe_filter->sf_filter.sf_attach(&entry->sfe_cookie, so);
			if (sock_locked)
				socket_lock(so, 0);	
			
			filter->sf_usecount--;
			
			/* If the attach function returns an error, this filter is not attached */
			if (error) {
				FREE(entry, M_IFADDR);
				entry = NULL;
			}
		}
	}
	
	if (error == 0) {
		/* Put the entry in the socket list */
		entry->sfe_next_onsocket = so->so_filt;
		so->so_filt = entry;
		
		/* Put the entry in the filter list */
		entry->sfe_next_onfilter = filter->sf_entry_head;
		filter->sf_entry_head = entry;
		
		/* Incremenet the parent filter's usecount */
		filter->sf_usecount++;
	}
	
	if (didlock) {
		lck_mtx_unlock(sock_filter_lock);
	}
	
	return error;
}


/* sflt_detach_private
 *
 * Assumptions: if you pass 0 in for the second parameter, you are holding the
 * socket lock for the socket the entry is attached to. If you pass 1 in for
 * the second parameter, it is assumed that the entry is not on the filter's
 * list and the socket lock is not held.
 */

static void
sflt_detach_private(
	struct socket_filter_entry *entry,
	int	unregistering)
{
	struct socket_filter_entry **next_ptr;
	int				detached = 0;
	int				found = 0;
	
	if (unregistering) {
		socket_lock(entry->sfe_socket, 0);
	}
	
	/*
	 * Attempt to find the entry on the filter's list and
	 * remove it. This prevents a filter detaching at the
	 * same time from attempting to remove the same entry.
	 */
	lck_mtx_lock(sock_filter_lock);
	if (!unregistering) {
		if ((entry->sfe_flags & SFEF_UNREGISTERING) != 0) {
			/*
			 * Another thread is unregistering the filter, we
			 * need to avoid detaching the filter here so the
			 * socket won't go away.  Bump up the socket's
			 * usecount so that it won't be freed until after
			 * the filter unregistration has been completed;
			 * at this point the caller has already held the
			 * socket's lock, so we can directly modify the
			 * usecount.
			 */
			if (!(entry->sfe_flags & SFEF_DETACHXREF)) {
				entry->sfe_socket->so_usecount++;
				entry->sfe_flags |= SFEF_DETACHXREF;
			}
			lck_mtx_unlock(sock_filter_lock);
			return;
		}
		for (next_ptr = &entry->sfe_filter->sf_entry_head; *next_ptr;
			 next_ptr = &((*next_ptr)->sfe_next_onfilter)) {
			if (*next_ptr == entry) {
				found = 1;
				*next_ptr = entry->sfe_next_onfilter;
				break;
			}
		}
		
		if (!found && (entry->sfe_flags & SFEF_DETACHUSEZERO) == 0) {
			lck_mtx_unlock(sock_filter_lock);
			return;
		}
	} else {
		/*
		 * Clear the removing flag. We will perform the detach here or
		 * request a delayed detach.  Since we do an extra ref release
		 * below, bump up the usecount if we haven't done so.
		 */
		entry->sfe_flags &= ~SFEF_UNREGISTERING;
		if (!(entry->sfe_flags & SFEF_DETACHXREF)) {
			entry->sfe_socket->so_usecount++;
			entry->sfe_flags |= SFEF_DETACHXREF;
		}
	}

	if (entry->sfe_socket->so_filteruse != 0) {
		entry->sfe_flags |= SFEF_DETACHUSEZERO;
		lck_mtx_unlock(sock_filter_lock);
	
		if (unregistering) {
#if DEBUG
			printf("sflt_detach_private unregistering SFEF_DETACHUSEZERO "
				"so%p so_filteruse %u so_usecount %d\n",
				entry->sfe_socket, entry->sfe_socket->so_filteruse, 
				entry->sfe_socket->so_usecount);
#endif
			socket_unlock(entry->sfe_socket, 0);	
		}
		return;
	} else {
		/*
		 * Check if we are removing the last attached filter and
		 * the parent filter is being unregistered.
		 */
		entry->sfe_filter->sf_usecount--;
		if ((entry->sfe_filter->sf_usecount == 0) &&
			(entry->sfe_filter->sf_flags & SFF_DETACHING) != 0)
			detached = 1;
	}
	lck_mtx_unlock(sock_filter_lock);
		
	/* Remove from the socket list */
	for (next_ptr = &entry->sfe_socket->so_filt; *next_ptr;
		 next_ptr = &((*next_ptr)->sfe_next_onsocket)) {
		if (*next_ptr == entry) {
			*next_ptr = entry->sfe_next_onsocket;
			break;
		}
	}
	
	if (entry->sfe_filter->sf_filter.sf_detach)
		entry->sfe_filter->sf_filter.sf_detach(entry->sfe_cookie, entry->sfe_socket);
	
	if (detached && entry->sfe_filter->sf_filter.sf_unregistered) {
		entry->sfe_filter->sf_filter.sf_unregistered(entry->sfe_filter->sf_filter.sf_handle);
		FREE(entry->sfe_filter, M_IFADDR);
	}

	if (unregistering) 
		socket_unlock(entry->sfe_socket, 1);

	FREE(entry, M_IFADDR);
}

errno_t
sflt_attach(
	socket_t	socket,
	sflt_handle	handle)
{
	if (socket == NULL || handle == 0)
		return EINVAL;
	
	return sflt_attach_private(socket, NULL, handle, 0);
}

errno_t
sflt_detach(
	socket_t	socket,
	sflt_handle	handle)
{
	struct socket_filter_entry	*filter;
	errno_t	result = 0;
	
	if (socket == NULL || handle == 0)
		return EINVAL;
	
	socket_lock(socket, 1);
	
	for (filter = socket->so_filt; filter;
		 filter = filter->sfe_next_onsocket) {
		if (filter->sfe_filter->sf_filter.sf_handle == handle)
			break;
	}
	
	if (filter != NULL) {
		sflt_detach_private(filter, 0);
	}
	else {
		socket->so_filt = NULL;
		result = ENOENT;
	}
	
	socket_unlock(socket, 1);
	
	return result;
}


errno_t
sflt_register(
	const struct sflt_filter	*filter,
	int				domain,
	int				type,
	int				protocol)
{
	struct socket_filter *sock_filt = NULL;
	struct socket_filter *match = NULL;
	int error = 0;
	struct protosw *pr = pffindproto(domain, protocol, type);
	unsigned int len;

	if (pr == NULL)
		return ENOENT;

	if (filter->sf_attach == NULL || filter->sf_detach == NULL ||
	    filter->sf_handle == 0 || filter->sf_name == NULL)
		return EINVAL;

	/* Allocate the socket filter */
	MALLOC(sock_filt, struct socket_filter *, sizeof (*sock_filt),
	    M_IFADDR, M_WAITOK);
	if (sock_filt == NULL) {
		return ENOBUFS;
	}

	bzero(sock_filt, sizeof (*sock_filt));

	/* Legacy sflt_filter length; current structure minus extended */
	len = sizeof (*filter) - sizeof (struct sflt_filter_ext);
	/*
	 * Include extended fields if filter defines SFLT_EXTENDED.
	 * We've zeroed out our internal sflt_filter placeholder,
	 * so any unused portion would have been taken care of.
	 */
	if (filter->sf_flags & SFLT_EXTENDED) {
		unsigned int ext_len = filter->sf_len;

		if (ext_len > sizeof (struct sflt_filter_ext))
			ext_len = sizeof (struct sflt_filter_ext);

		len += ext_len;
	}
	bcopy(filter, &sock_filt->sf_filter, len);

	lck_mtx_lock(sock_filter_lock);
	/* Look for an existing entry */
	TAILQ_FOREACH(match, &sock_filter_head, sf_global_next) {
		if (match->sf_filter.sf_handle ==
		    sock_filt->sf_filter.sf_handle) {
			break;
		}
	}

	/* Add the entry only if there was no existing entry */
	if (match == NULL) {
		TAILQ_INSERT_TAIL(&sock_filter_head, sock_filt, sf_global_next);
		if ((sock_filt->sf_filter.sf_flags & SFLT_GLOBAL) != 0) {
			TAILQ_INSERT_TAIL(&pr->pr_filter_head, sock_filt,
			    sf_protosw_next);
			sock_filt->sf_proto = pr;
		}
	}
	lck_mtx_unlock(sock_filter_lock);

	if (match != NULL) {
		FREE(sock_filt, M_IFADDR);
		return EEXIST;
	}

	return error;
}

errno_t
sflt_unregister(
	sflt_handle handle)
{
	struct socket_filter *filter;
	struct socket_filter_entry *entry_head = NULL;
	struct socket_filter_entry *next_entry = NULL;
	
	/* Find the entry and remove it from the global and protosw lists */
	lck_mtx_lock(sock_filter_lock);
	TAILQ_FOREACH(filter, &sock_filter_head, sf_global_next) {
		if (filter->sf_filter.sf_handle == handle)
			break;
	}
	
	if (filter) {
		TAILQ_REMOVE(&sock_filter_head, filter, sf_global_next);
		if ((filter->sf_filter.sf_flags & SFLT_GLOBAL) != 0) {
			TAILQ_REMOVE(&filter->sf_proto->pr_filter_head, filter, sf_protosw_next);
		}
		entry_head = filter->sf_entry_head;
		filter->sf_entry_head = NULL;
		filter->sf_flags |= SFF_DETACHING;
	
		for (next_entry = entry_head; next_entry;
		    next_entry = next_entry->sfe_next_onfilter) {
			/*
			 * Mark this as "unregistering"; upon dropping the
			 * lock, another thread may win the race and attempt
			 * to detach a socket from it (e.g. as part of close)
			 * before we get a chance to detach.  Setting this
			 * flag practically tells the other thread to go away.
			 * If the other thread wins, this causes an extra
			 * reference hold on the socket so that it won't be
			 * deallocated until after we finish with the detach
			 * for it below.  If we win the race, the extra
			 * reference hold is also taken to compensate for the
			 * extra reference release when detach is called
			 * with a "1" for its second parameter.
			 */
			next_entry->sfe_flags |= SFEF_UNREGISTERING;
		}
	}
	
	lck_mtx_unlock(sock_filter_lock);
	
	if (filter == NULL)
		return ENOENT;
	
	/* We need to detach the filter from any sockets it's attached to */
	if (entry_head == 0) {
		if (filter->sf_filter.sf_unregistered)
			filter->sf_filter.sf_unregistered(filter->sf_filter.sf_handle);
	} else {
		while (entry_head) {
			next_entry = entry_head->sfe_next_onfilter;
			sflt_detach_private(entry_head, 1);
			entry_head = next_entry;
		}
	}
	
	return 0;
}

errno_t
sock_inject_data_in(
	socket_t so,
	const struct sockaddr* from,
	mbuf_t data,
	mbuf_t control,
	sflt_data_flag_t flags)
{
	int error = 0;
	if (so == NULL || data == NULL) return EINVAL;
	
	if (flags & sock_data_filt_flag_oob) {
		return ENOTSUP;
	}
	
	socket_lock(so, 1);
	
	if (from) {
		if (sbappendaddr(&so->so_rcv, (struct sockaddr*)(uintptr_t)from, data,
						 control, NULL))
			sorwakeup(so);
		goto done;
	}
	
	if (control) {
		if (sbappendcontrol(&so->so_rcv, data, control, NULL))
			sorwakeup(so);
		goto done;
	}
	
	if (flags & sock_data_filt_flag_record) {
		if (control || from) {
			error = EINVAL;
			goto done;
		}
		if (sbappendrecord(&so->so_rcv, (struct mbuf*)data))
			sorwakeup(so);
		goto done;
	}
	
	if (sbappend(&so->so_rcv, data))
		sorwakeup(so);
done:
	socket_unlock(so, 1);
	return error;
}

errno_t
sock_inject_data_out(
	socket_t so,
	const struct sockaddr* to,
	mbuf_t data,
	mbuf_t control,
	sflt_data_flag_t flags)
{
	int	sosendflags = 0;
	if (flags & sock_data_filt_flag_oob) sosendflags = MSG_OOB;
	return sosend(so, (struct sockaddr*)(uintptr_t)to, NULL,
				  data, control, sosendflags);
}

sockopt_dir
sockopt_direction(
	sockopt_t	sopt)
{
	return (sopt->sopt_dir == SOPT_GET) ? sockopt_get : sockopt_set;
}

int
sockopt_level(
	sockopt_t	sopt)
{
	return sopt->sopt_level;
}

int
sockopt_name(
	sockopt_t	sopt)
{
	return sopt->sopt_name;
}

size_t
sockopt_valsize(
	sockopt_t	sopt)
{
	return sopt->sopt_valsize;
}

errno_t
sockopt_copyin(
	sockopt_t	sopt,
	void *data,
	size_t	len)
{
	return sooptcopyin(sopt, data, len, len);
}

errno_t
sockopt_copyout(
	sockopt_t	sopt,
	void *data,
	size_t	len)
{
	return sooptcopyout(sopt, data, len);
}
