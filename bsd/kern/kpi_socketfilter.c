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
#include <sys/proc.h>
#include <kern/locks.h>
#include <kern/thread.h>
#include <kern/debug.h>
#include <net/kext_net.h>

#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>

#include <string.h>

#define	SFEF_ATTACHED		0x1	/* SFE is on socket list */
#define	SFEF_NODETACH		0x2	/* Detach should not be called */
#define	SFEF_NOSOCKET		0x4	/* Socket is gone */

struct socket_filter_entry {
	struct socket_filter_entry	*sfe_next_onsocket;
	struct socket_filter_entry	*sfe_next_onfilter;
	struct socket_filter_entry	*sfe_next_oncleanup;
	
	struct socket_filter		*sfe_filter;
	struct socket				*sfe_socket;
	void						*sfe_cookie;
	
	uint32_t					sfe_flags;
	int32_t						sfe_refcount;
};

struct socket_filter {
	TAILQ_ENTRY(socket_filter)	sf_protosw_next;	
	TAILQ_ENTRY(socket_filter)	sf_global_next;
	struct socket_filter_entry	*sf_entry_head;
	
	struct protosw				*sf_proto;
	struct sflt_filter			sf_filter;
	u_int32_t					sf_refcount;
};

TAILQ_HEAD(socket_filter_list, socket_filter);

static struct socket_filter_list	sock_filter_head;
static lck_rw_t						*sock_filter_lock = NULL;
static lck_mtx_t					*sock_filter_cleanup_lock = NULL;
static struct socket_filter_entry	*sock_filter_cleanup_entries = NULL;
static thread_t						sock_filter_cleanup_thread = NULL;

static void sflt_cleanup_thread(void *, wait_result_t);
static void sflt_detach_locked(struct socket_filter_entry *entry);

#pragma mark -- Internal State Management --

__private_extern__ void
sflt_init(void)
{
	lck_grp_attr_t	*grp_attrib = 0;
	lck_attr_t		*lck_attrib = 0;
	lck_grp_t		*lck_group = 0;
	
	TAILQ_INIT(&sock_filter_head);
	
	/* Allocate a rw lock */
	grp_attrib = lck_grp_attr_alloc_init();
	lck_group = lck_grp_alloc_init("socket filter lock", grp_attrib);
	lck_grp_attr_free(grp_attrib);
	lck_attrib = lck_attr_alloc_init();
	sock_filter_lock = lck_rw_alloc_init(lck_group, lck_attrib);
	sock_filter_cleanup_lock = lck_mtx_alloc_init(lck_group, lck_attrib);
	lck_grp_free(lck_group);
	lck_attr_free(lck_attrib);
}

static void
sflt_retain_locked(
	struct socket_filter	*filter)
{
	filter->sf_refcount++;
}

static void
sflt_release_locked(
	struct socket_filter	*filter)
{
	filter->sf_refcount--;
	if (filter->sf_refcount == 0)
	{
		// Call the unregistered function
		if (filter->sf_filter.sf_unregistered) {
			lck_rw_unlock_exclusive(sock_filter_lock);
			filter->sf_filter.sf_unregistered(filter->sf_filter.sf_handle);
			lck_rw_lock_exclusive(sock_filter_lock);
		}
		
		// Free the entry
		FREE(filter, M_IFADDR);
	}
}

static void
sflt_entry_retain(
	struct socket_filter_entry *entry)
{
	if (OSIncrementAtomic(&entry->sfe_refcount) <= 0)
		panic("sflt_entry_retain - sfe_refcount <= 0\n");
}

static void
sflt_entry_release(
	struct socket_filter_entry *entry)
{
	SInt32 old = OSDecrementAtomic(&entry->sfe_refcount);
	if (old == 1) {
		// That was the last reference
		
		// Take the cleanup lock
		lck_mtx_lock(sock_filter_cleanup_lock);
		
		// Put this item on the cleanup list
		entry->sfe_next_oncleanup = sock_filter_cleanup_entries;
		sock_filter_cleanup_entries = entry;
		
		// If the item is the first item in the list
		if (entry->sfe_next_oncleanup == NULL) {
			if (sock_filter_cleanup_thread == NULL) {
				// Create a thread
				kernel_thread_start(sflt_cleanup_thread, NULL, &sock_filter_cleanup_thread);
			} else {
				// Wakeup the thread
				wakeup(&sock_filter_cleanup_entries);
			}
		}
		
		// Drop the cleanup lock
		lck_mtx_unlock(sock_filter_cleanup_lock);
	}
	else if (old <= 0)
	{
		panic("sflt_entry_release - sfe_refcount (%d) <= 0\n", (int)old);
	}
}

static void
sflt_cleanup_thread(
	__unused void * blah,
	__unused wait_result_t blah2)
{
	while (1) {
		lck_mtx_lock(sock_filter_cleanup_lock);
		while (sock_filter_cleanup_entries == NULL) {
			// Sleep until we've got something better to do
			msleep(&sock_filter_cleanup_entries, sock_filter_cleanup_lock, PWAIT, "sflt_cleanup", NULL);
		}
		
		// Pull the current list of dead items
		struct socket_filter_entry	*dead = sock_filter_cleanup_entries;
		sock_filter_cleanup_entries = NULL;
		
		// Drop the lock
		lck_mtx_unlock(sock_filter_cleanup_lock);
		
		// Take the socket filter lock
		lck_rw_lock_exclusive(sock_filter_lock);
		
		// Cleanup every dead item
		struct socket_filter_entry	*entry;
		for (entry = dead; entry; entry = dead) {
			struct socket_filter_entry	**nextpp;
			
			dead = entry->sfe_next_oncleanup;
			
			// Call the detach function if necessary - drop the lock
			if ((entry->sfe_flags & SFEF_NODETACH) == 0 &&
				entry->sfe_filter->sf_filter.sf_detach) {
				entry->sfe_flags |= SFEF_NODETACH;
				lck_rw_unlock_exclusive(sock_filter_lock);
				
				// Warning - passing a potentially dead socket may be bad
				entry->sfe_filter->sf_filter.
					sf_detach(entry->sfe_cookie, entry->sfe_socket);
				
				lck_rw_lock_exclusive(sock_filter_lock);
			}
			
			// Pull entry off the socket list -- if the socket still exists
			if ((entry->sfe_flags & SFEF_NOSOCKET) == 0) {
				for (nextpp = &entry->sfe_socket->so_filt; *nextpp;
					 nextpp = &(*nextpp)->sfe_next_onsocket) {
					if (*nextpp == entry) {
						*nextpp = entry->sfe_next_onsocket;
						break;
					}
				}
			}
			
			// Pull entry off the filter list
			for (nextpp = &entry->sfe_filter->sf_entry_head; *nextpp;
				 nextpp = &(*nextpp)->sfe_next_onfilter) {
				if (*nextpp == entry) {
					*nextpp = entry->sfe_next_onfilter;
					break;
				}
			}
			
			// Release the filter -- may drop lock, but that's okay
			sflt_release_locked(entry->sfe_filter);
			entry->sfe_socket = NULL;
			entry->sfe_filter = NULL;
			FREE(entry, M_IFADDR);
		}
		
		// Drop the socket filter lock
		lck_rw_unlock_exclusive(sock_filter_lock);
	}
	// Not reached
}

static int
sflt_attach_locked(
	struct socket			*so,
	struct socket_filter	*filter,
	int						socklocked)
{
	int error = 0;
	struct socket_filter_entry *entry = NULL;
	
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
		/* Initialize the socket filter entry */
		entry->sfe_cookie = NULL;
		entry->sfe_flags = SFEF_ATTACHED;
		entry->sfe_refcount = 1; // corresponds to SFEF_ATTACHED flag set
		
		/* Put the entry in the filter list */
		sflt_retain_locked(filter);
		entry->sfe_filter = filter;
		entry->sfe_next_onfilter = filter->sf_entry_head;
		filter->sf_entry_head = entry;
		
		/* Put the entry on the socket filter list */
		entry->sfe_socket = so;
		entry->sfe_next_onsocket = so->so_filt;
		so->so_filt = entry;
		
		if (entry->sfe_filter->sf_filter.sf_attach) {
			// Retain the entry while we call attach
			sflt_entry_retain(entry);
			
			// Release the filter lock -- callers must be aware we will do this
			lck_rw_unlock_exclusive(sock_filter_lock);
			
			// Unlock the socket
			if (socklocked)
				socket_unlock(so, 0);
			
			// It's finally safe to call the filter function
			error = entry->sfe_filter->sf_filter.sf_attach(&entry->sfe_cookie, so);
			
			// Lock the socket again
			if (socklocked)
				socket_lock(so, 0);
			
			// Lock the filters again
			lck_rw_lock_exclusive(sock_filter_lock);
			
			// If the attach function returns an error, this filter must be detached
			if (error) {
				entry->sfe_flags |= SFEF_NODETACH; // don't call sf_detach
				sflt_detach_locked(entry);
			}
			
			// Release the retain we held through the attach call
			sflt_entry_release(entry);
		}
	}
	
	return error;
}

errno_t
sflt_attach_internal(
	socket_t	socket,
	sflt_handle	handle)
{
	if (socket == NULL || handle == 0)
		return EINVAL;
	
	int result = EINVAL;
	
	lck_rw_lock_exclusive(sock_filter_lock);
	
	struct socket_filter *filter = NULL;
	TAILQ_FOREACH(filter, &sock_filter_head, sf_global_next) {
		if (filter->sf_filter.sf_handle == handle) break;
	}
	
	if (filter) {
		result = sflt_attach_locked(socket, filter, 1);
	}
	
	lck_rw_unlock_exclusive(sock_filter_lock);
	
	return result;
}

static void
sflt_detach_locked(
	struct socket_filter_entry	*entry)
{
	if ((entry->sfe_flags & SFEF_ATTACHED) != 0) {
		entry->sfe_flags &= ~SFEF_ATTACHED;
		sflt_entry_release(entry);
	}
}

#pragma mark -- Socket Layer Hooks --

__private_extern__ void
sflt_initsock(
	struct socket *so)
{
	struct protosw *proto = so->so_proto;
	
	lck_rw_lock_shared(sock_filter_lock);
	if (TAILQ_FIRST(&proto->pr_filter_head) != NULL) {
		// Promote lock to exclusive
		if (!lck_rw_lock_shared_to_exclusive(sock_filter_lock))
			lck_rw_lock_exclusive(sock_filter_lock);
		
		// Warning: A filter unregistering will be pulled out of the list.
		// This could happen while we drop the lock in sftl_attach_locked
		// or sflt_release_locked. For this reason we retain a reference
		// on the filter (or next_filter) while calling this function
		//
		// This protects us from a panic, but it could result in a
		// socket being created without all of the global filters if
		// we're attaching a filter as it is removed, if that's possible.
		struct socket_filter *filter = TAILQ_FIRST(&proto->pr_filter_head);
		sflt_retain_locked(filter);
		
		while (filter)
		{
			struct socket_filter *filter_next;
			
			// Warning: sflt_attach_private_locked will drop the lock
			sflt_attach_locked(so, filter, 0);
			
			filter_next = TAILQ_NEXT(filter, sf_protosw_next);
			if (filter_next)
				sflt_retain_locked(filter_next);
			
			// Warning: filt_release_locked may remove the filter from the queue
			sflt_release_locked(filter);
			filter = filter_next;
		}
	}
	lck_rw_done(sock_filter_lock);
}

/*
 * sflt_termsock
 *
 * Detaches all filters from the socket.
 */

__private_extern__ void
sflt_termsock(
	struct socket *so)
{
	lck_rw_lock_exclusive(sock_filter_lock);
	
	struct socket_filter_entry *entry;
	
	while ((entry = so->so_filt) != NULL) {
		// Pull filter off the socket
		so->so_filt = entry->sfe_next_onsocket;
		entry->sfe_flags |= SFEF_NOSOCKET;
		
		// Call detach
		sflt_detach_locked(entry);
		
		// On sflt_termsock, we can't return until the detach function has been called
		// Call the detach function - this is gross because the socket filter
		// entry could be freed when we drop the lock, so we make copies on
		// the stack and retain everything we need before dropping the lock
		if ((entry->sfe_flags & SFEF_NODETACH) == 0 &&
			entry->sfe_filter->sf_filter.sf_detach) {
			void					*sfe_cookie = entry->sfe_cookie;
			struct socket_filter	*sfe_filter = entry->sfe_filter;
			
			// Retain the socket filter
			sflt_retain_locked(sfe_filter);
			
			// Mark that we've called the detach function
			entry->sfe_flags |= SFEF_NODETACH;
			
			// Drop the lock around the call to the detach function
			lck_rw_unlock_exclusive(sock_filter_lock);
			sfe_filter->sf_filter.sf_detach(sfe_cookie, so);
			lck_rw_lock_exclusive(sock_filter_lock);
			
			// Release the filter
			sflt_release_locked(sfe_filter);
		}
	}
	
	lck_rw_unlock_exclusive(sock_filter_lock);
}

__private_extern__ void
sflt_notify(
	struct socket	*so,
	sflt_event_t	event,
	void			*param)
{
	if (so->so_filt == NULL) return;
	
	struct socket_filter_entry	*entry;
	int						 	unlocked = 0;
	
	lck_rw_lock_shared(sock_filter_lock);
	for (entry = so->so_filt; entry; entry = entry->sfe_next_onsocket) {
		if ((entry->sfe_flags & SFEF_ATTACHED)
			&& entry->sfe_filter->sf_filter.sf_notify) {
			// Retain the filter entry and release the socket filter lock
			sflt_entry_retain(entry);
			lck_rw_unlock_shared(sock_filter_lock);
			
			// If the socket isn't already unlocked, unlock it
			if (unlocked == 0) {
				unlocked = 1;
				socket_unlock(so, 0);
			}
			
			// Finally call the filter
			entry->sfe_filter->sf_filter.
				sf_notify(entry->sfe_cookie, so, event, param);
			
			// Take the socket filter lock again and release the entry
			lck_rw_lock_shared(sock_filter_lock);
			sflt_entry_release(entry);
		}
	}
	lck_rw_unlock_shared(sock_filter_lock);
	
	if (unlocked != 0) {
		socket_lock(so, 0);
	}
}

__private_extern__ int
sflt_ioctl(
	struct socket	*so,
	u_long			cmd,
	caddr_t			data)
{
	if (so->so_filt == NULL) return 0;
	
	struct socket_filter_entry	*entry;
	int						 	unlocked = 0;
	int							error = 0;
	
	lck_rw_lock_shared(sock_filter_lock);
	for (entry = so->so_filt; entry && error == 0;
		 entry = entry->sfe_next_onsocket) {
		if ((entry->sfe_flags & SFEF_ATTACHED)
			&& entry->sfe_filter->sf_filter.sf_ioctl) {
			// Retain the filter entry and release the socket filter lock
			sflt_entry_retain(entry);
			lck_rw_unlock_shared(sock_filter_lock);
			
			// If the socket isn't already unlocked, unlock it
			if (unlocked == 0) {
				socket_unlock(so, 0);
				unlocked = 1;
			}
			
			// Call the filter
			error = entry->sfe_filter->sf_filter.
				sf_ioctl(entry->sfe_cookie, so, cmd, data);
			
			// Take the socket filter lock again and release the entry
			lck_rw_lock_shared(sock_filter_lock);
			sflt_entry_release(entry);
		}
	}
	lck_rw_unlock_shared(sock_filter_lock);

	if (unlocked) {
		socket_lock(so, 0);
	}
	
	return error;
}

__private_extern__ int
sflt_bind(
	struct socket			*so,
	const struct sockaddr	*nam)
{
	if (so->so_filt == NULL) return 0;
	
	struct socket_filter_entry	*entry;
	int						 	unlocked = 0;
	int							error = 0;
	
	lck_rw_lock_shared(sock_filter_lock);
	for (entry = so->so_filt; entry && error == 0;
		 entry = entry->sfe_next_onsocket) {
		if ((entry->sfe_flags & SFEF_ATTACHED)
			&& entry->sfe_filter->sf_filter.sf_bind) {
			// Retain the filter entry and release the socket filter lock
			sflt_entry_retain(entry);
			lck_rw_unlock_shared(sock_filter_lock);
			
			// If the socket isn't already unlocked, unlock it
			if (unlocked == 0) {
				socket_unlock(so, 0);
				unlocked = 1;
			}
			
			// Call the filter
			error = entry->sfe_filter->sf_filter.
				sf_bind(entry->sfe_cookie, so, nam);
			
			// Take the socket filter lock again and release the entry
			lck_rw_lock_shared(sock_filter_lock);
			sflt_entry_release(entry);
		}
	}
	lck_rw_unlock_shared(sock_filter_lock);

	if (unlocked) {
		socket_lock(so, 0);
	}
	
	return error;
}

__private_extern__ int
sflt_listen(
	struct socket			*so)
{
	if (so->so_filt == NULL) return 0;
	
	struct socket_filter_entry	*entry;
	int						 	unlocked = 0;
	int							error = 0;
	
	lck_rw_lock_shared(sock_filter_lock);
	for (entry = so->so_filt; entry && error == 0;
		 entry = entry->sfe_next_onsocket) {
		if ((entry->sfe_flags & SFEF_ATTACHED)
			&& entry->sfe_filter->sf_filter.sf_listen) {
			// Retain the filter entry and release the socket filter lock
			sflt_entry_retain(entry);
			lck_rw_unlock_shared(sock_filter_lock);
			
			// If the socket isn't already unlocked, unlock it
			if (unlocked == 0) {
				socket_unlock(so, 0);
				unlocked = 1;
			}
			
			// Call the filter
			error = entry->sfe_filter->sf_filter.
				sf_listen(entry->sfe_cookie, so);
			
			// Take the socket filter lock again and release the entry
			lck_rw_lock_shared(sock_filter_lock);
			sflt_entry_release(entry);
		}
	}
	lck_rw_unlock_shared(sock_filter_lock);

	if (unlocked) {
		socket_lock(so, 0);
	}
	
	return error;
}

__private_extern__ int
sflt_accept(
	struct socket			*head,
	struct socket			*so,
	const struct sockaddr	*local,
	const struct sockaddr	*remote)
{
	if (so->so_filt == NULL) return 0;
	
	struct socket_filter_entry	*entry;
	int						 	unlocked = 0;
	int							error = 0;
	
	lck_rw_lock_shared(sock_filter_lock);
	for (entry = so->so_filt; entry && error == 0;
		 entry = entry->sfe_next_onsocket) {
		if ((entry->sfe_flags & SFEF_ATTACHED)
			&& entry->sfe_filter->sf_filter.sf_accept) {
			// Retain the filter entry and release the socket filter lock
			sflt_entry_retain(entry);
			lck_rw_unlock_shared(sock_filter_lock);
			
			// If the socket isn't already unlocked, unlock it
			if (unlocked == 0) {
				socket_unlock(so, 0);
				unlocked = 1;
			}
			
			// Call the filter
			error = entry->sfe_filter->sf_filter.
				sf_accept(entry->sfe_cookie, head, so, local, remote);
			
			// Take the socket filter lock again and release the entry
			lck_rw_lock_shared(sock_filter_lock);
			sflt_entry_release(entry);
		}
	}
	lck_rw_unlock_shared(sock_filter_lock);

	if (unlocked) {
		socket_lock(so, 0);
	}
	
	return error;
}

__private_extern__ int
sflt_getsockname(
	struct socket			*so,
	struct sockaddr			**local)
{
	if (so->so_filt == NULL) return 0;
	
	struct socket_filter_entry	*entry;
	int						 	unlocked = 0;
	int							error = 0;
	
	lck_rw_lock_shared(sock_filter_lock);
	for (entry = so->so_filt; entry && error == 0;
		 entry = entry->sfe_next_onsocket) {
		if ((entry->sfe_flags & SFEF_ATTACHED)
			&& entry->sfe_filter->sf_filter.sf_getsockname) {
			// Retain the filter entry and release the socket filter lock
			sflt_entry_retain(entry);
			lck_rw_unlock_shared(sock_filter_lock);
			
			// If the socket isn't already unlocked, unlock it
			if (unlocked == 0) {
				socket_unlock(so, 0);
				unlocked = 1;
			}
			
			// Call the filter
			error = entry->sfe_filter->sf_filter.
				sf_getsockname(entry->sfe_cookie, so, local);
			
			// Take the socket filter lock again and release the entry
			lck_rw_lock_shared(sock_filter_lock);
			sflt_entry_release(entry);
		}
	}
	lck_rw_unlock_shared(sock_filter_lock);

	if (unlocked) {
		socket_lock(so, 0);
	}
	
	return error;
}

__private_extern__ int
sflt_getpeername(
	struct socket			*so,
	struct sockaddr			**remote)
{
	if (so->so_filt == NULL) return 0;
	
	struct socket_filter_entry	*entry;
	int						 	unlocked = 0;
	int							error = 0;
	
	lck_rw_lock_shared(sock_filter_lock);
	for (entry = so->so_filt; entry && error == 0;
		 entry = entry->sfe_next_onsocket) {
		if ((entry->sfe_flags & SFEF_ATTACHED)
			&& entry->sfe_filter->sf_filter.sf_getpeername) {
			// Retain the filter entry and release the socket filter lock
			sflt_entry_retain(entry);
			lck_rw_unlock_shared(sock_filter_lock);
			
			// If the socket isn't already unlocked, unlock it
			if (unlocked == 0) {
				socket_unlock(so, 0);
				unlocked = 1;
			}
			
			// Call the filter
			error = entry->sfe_filter->sf_filter.
				sf_getpeername(entry->sfe_cookie, so, remote);
			
			// Take the socket filter lock again and release the entry
			lck_rw_lock_shared(sock_filter_lock);
			sflt_entry_release(entry);
		}
	}
	lck_rw_unlock_shared(sock_filter_lock);

	if (unlocked) {
		socket_lock(so, 0);
	}
	
	return error;
}

__private_extern__ int
sflt_connectin(
	struct socket			*so,
	const struct sockaddr	*remote)
{
	if (so->so_filt == NULL) return 0;
	
	struct socket_filter_entry	*entry;
	int						 	unlocked = 0;
	int							error = 0;
	
	lck_rw_lock_shared(sock_filter_lock);
	for (entry = so->so_filt; entry && error == 0;
		 entry = entry->sfe_next_onsocket) {
		if ((entry->sfe_flags & SFEF_ATTACHED)
			&& entry->sfe_filter->sf_filter.sf_connect_in) {
			// Retain the filter entry and release the socket filter lock
			sflt_entry_retain(entry);
			lck_rw_unlock_shared(sock_filter_lock);
			
			// If the socket isn't already unlocked, unlock it
			if (unlocked == 0) {
				socket_unlock(so, 0);
				unlocked = 1;
			}
			
			// Call the filter
			error = entry->sfe_filter->sf_filter.
				sf_connect_in(entry->sfe_cookie, so, remote);
			
			// Take the socket filter lock again and release the entry
			lck_rw_lock_shared(sock_filter_lock);
			sflt_entry_release(entry);
		}
	}
	lck_rw_unlock_shared(sock_filter_lock);

	if (unlocked) {
		socket_lock(so, 0);
	}
	
	return error;
}

__private_extern__ int
sflt_connectout(
	struct socket			*so,
	const struct sockaddr	*nam)
{
	if (so->so_filt == NULL) return 0;
	
	struct socket_filter_entry	*entry;
	int						 	unlocked = 0;
	int							error = 0;
	
	lck_rw_lock_shared(sock_filter_lock);
	for (entry = so->so_filt; entry && error == 0;
		 entry = entry->sfe_next_onsocket) {
		if ((entry->sfe_flags & SFEF_ATTACHED)
			&& entry->sfe_filter->sf_filter.sf_connect_out) {
			// Retain the filter entry and release the socket filter lock
			sflt_entry_retain(entry);
			lck_rw_unlock_shared(sock_filter_lock);
			
			// If the socket isn't already unlocked, unlock it
			if (unlocked == 0) {
				socket_unlock(so, 0);
				unlocked = 1;
			}
			
			// Call the filter
			error = entry->sfe_filter->sf_filter.
				sf_connect_out(entry->sfe_cookie, so, nam);
			
			// Take the socket filter lock again and release the entry
			lck_rw_lock_shared(sock_filter_lock);
			sflt_entry_release(entry);
		}
	}
	lck_rw_unlock_shared(sock_filter_lock);

	if (unlocked) {
		socket_lock(so, 0);
	}
	
	return error;
}

__private_extern__ int
sflt_setsockopt(
	struct socket	*so,
	struct sockopt	*sopt)
{
	if (so->so_filt == NULL) return 0;
	
	struct socket_filter_entry	*entry;
	int						 	unlocked = 0;
	int							error = 0;
	
	lck_rw_lock_shared(sock_filter_lock);
	for (entry = so->so_filt; entry && error == 0;
		 entry = entry->sfe_next_onsocket) {
		if ((entry->sfe_flags & SFEF_ATTACHED)
			&& entry->sfe_filter->sf_filter.sf_setoption) {
			// Retain the filter entry and release the socket filter lock
			sflt_entry_retain(entry);
			lck_rw_unlock_shared(sock_filter_lock);
			
			// If the socket isn't already unlocked, unlock it
			if (unlocked == 0) {
				socket_unlock(so, 0);
				unlocked = 1;
			}
			
			// Call the filter
			error = entry->sfe_filter->sf_filter.
				sf_setoption(entry->sfe_cookie, so, sopt);
			
			// Take the socket filter lock again and release the entry
			lck_rw_lock_shared(sock_filter_lock);
			sflt_entry_release(entry);
		}
	}
	lck_rw_unlock_shared(sock_filter_lock);

	if (unlocked) {
		socket_lock(so, 0);
	}
	
	return error;
}

__private_extern__ int
sflt_getsockopt(
	struct socket	*so,
	struct sockopt	*sopt)
{
	if (so->so_filt == NULL) return 0;
	
	struct socket_filter_entry	*entry;
	int						 	unlocked = 0;
	int							error = 0;
	
	lck_rw_lock_shared(sock_filter_lock);
	for (entry = so->so_filt; entry && error == 0;
		 entry = entry->sfe_next_onsocket) {
		if ((entry->sfe_flags & SFEF_ATTACHED)
			&& entry->sfe_filter->sf_filter.sf_getoption) {
			// Retain the filter entry and release the socket filter lock
			sflt_entry_retain(entry);
			lck_rw_unlock_shared(sock_filter_lock);
			
			// If the socket isn't already unlocked, unlock it
			if (unlocked == 0) {
				socket_unlock(so, 0);
				unlocked = 1;
			}
			
			// Call the filter
			error = entry->sfe_filter->sf_filter.
				sf_getoption(entry->sfe_cookie, so, sopt);
			
			// Take the socket filter lock again and release the entry
			lck_rw_lock_shared(sock_filter_lock);
			sflt_entry_release(entry);
		}
	}
	lck_rw_unlock_shared(sock_filter_lock);

	if (unlocked) {
		socket_lock(so, 0);
	}
	
	return error;
}

__private_extern__ int
sflt_data_out(
	struct socket			*so,
	const struct sockaddr	*to,
	mbuf_t					*data,
	mbuf_t					*control,
	sflt_data_flag_t		flags)
{
	if (so->so_filt == NULL) return 0;
	
	struct socket_filter_entry	*entry;
	int						 	unlocked = 0;
	int							setsendthread = 0;
	int							error = 0;
	
	lck_rw_lock_shared(sock_filter_lock);
	for (entry = so->so_filt; entry && error == 0;
		 entry = entry->sfe_next_onsocket) {
		if ((entry->sfe_flags & SFEF_ATTACHED)
			&& entry->sfe_filter->sf_filter.sf_data_out) {
			// Retain the filter entry and release the socket filter lock
			sflt_entry_retain(entry);
			lck_rw_unlock_shared(sock_filter_lock);
			
			// If the socket isn't already unlocked, unlock it
			if (unlocked == 0) {
				if (so->so_send_filt_thread == NULL) {
					setsendthread = 1;
					so->so_send_filt_thread = current_thread();
				}
				socket_unlock(so, 0);
				unlocked = 1;
			}
			
			// Call the filter
			error = entry->sfe_filter->sf_filter.
				sf_data_out(entry->sfe_cookie, so, to, data, control, flags);
			
			// Take the socket filter lock again and release the entry
			lck_rw_lock_shared(sock_filter_lock);
			sflt_entry_release(entry);
		}
	}
	lck_rw_unlock_shared(sock_filter_lock);

	if (unlocked) {
		socket_lock(so, 0);
		if (setsendthread) so->so_send_filt_thread = NULL;
	}
	
	return error;
}

__private_extern__ int
sflt_data_in(
	struct socket			*so,
	const struct sockaddr	*from,
	mbuf_t					*data,
	mbuf_t					*control,
	sflt_data_flag_t		flags)
{
	if (so->so_filt == NULL) return 0;
	
	struct socket_filter_entry	*entry;
	int							error = 0;
	int							unlocked = 0;
	
	lck_rw_lock_shared(sock_filter_lock);
	
	for (entry = so->so_filt; entry && (error == 0);
		 entry = entry->sfe_next_onsocket) {
		if ((entry->sfe_flags & SFEF_ATTACHED) &&
			entry->sfe_filter->sf_filter.sf_data_in) {
			// Retain the filter entry and release the socket filter lock
			sflt_entry_retain(entry);
			lck_rw_unlock_shared(sock_filter_lock);
			
			// If the socket isn't already unlocked, unlock it
			if (unlocked == 0) {
				unlocked = 1;
				socket_unlock(so, 0);
			}
			
			// Call the filter
			error = entry->sfe_filter->sf_filter.sf_data_in(
						entry->sfe_cookie, so, from, data, control, flags);
			
			// Take the socket filter lock again and release the entry
			lck_rw_lock_shared(sock_filter_lock);
			sflt_entry_release(entry);
		}
	}
	lck_rw_unlock_shared(sock_filter_lock);
	
	if (unlocked) {
		socket_lock(so, 0);
	}
	
	return error;
}

#pragma mark -- KPI --

errno_t
sflt_attach(
	socket_t	socket,
	sflt_handle	handle)
{
	socket_lock(socket, 1);
	errno_t result = sflt_attach_internal(socket, handle);
	socket_unlock(socket, 1);
	return result;
}

errno_t
sflt_detach(
	socket_t	socket,
	sflt_handle	handle)
{
	struct socket_filter_entry	*entry;
	errno_t	result = 0;
	
	if (socket == NULL || handle == 0)
		return EINVAL;
	
	lck_rw_lock_exclusive(sock_filter_lock);
	for (entry = socket->so_filt; entry;
		 entry = entry->sfe_next_onsocket) {
		if (entry->sfe_filter->sf_filter.sf_handle == handle &&
			(entry->sfe_flags & SFEF_ATTACHED) != 0) {
			break;
		}
	}
	
	if (entry != NULL) {
		sflt_detach_locked(entry);
	}
	lck_rw_unlock_exclusive(sock_filter_lock);
	
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

	lck_rw_lock_exclusive(sock_filter_lock);
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
		sflt_retain_locked(sock_filt);
	}
	lck_rw_unlock_exclusive(sock_filter_lock);
	
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
	lck_rw_lock_exclusive(sock_filter_lock);
	
	/* Find the entry by the handle */
	TAILQ_FOREACH(filter, &sock_filter_head, sf_global_next) {
		if (filter->sf_filter.sf_handle == handle)
			break;
	}
	
	if (filter) {
		// Remove it from the global list
		TAILQ_REMOVE(&sock_filter_head, filter, sf_global_next);
		
		// Remove it from the protosw list
		if ((filter->sf_filter.sf_flags & SFLT_GLOBAL) != 0) {
			TAILQ_REMOVE(&filter->sf_proto->pr_filter_head, filter, sf_protosw_next);
		}
		
		// Detach from any sockets
		struct socket_filter_entry *entry = NULL;
		
		for (entry = filter->sf_entry_head; entry; entry = entry->sfe_next_onfilter) {
			sflt_detach_locked(entry);
		}
		
		// Release the filter
		sflt_release_locked(filter);
	}
	
	lck_rw_unlock_exclusive(sock_filter_lock);
	
	if (filter == NULL)
		return ENOENT;
	
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
