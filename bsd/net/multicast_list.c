/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

/*
 * multicast_util.c:
 * - keep track of multicast addresses added to one interface based on the
 *   actual multicast addresses in another
 * - used by VLAN and BOND
 */

/*
 * Modification History:
 *
 * April 29, 2004	Dieter Siegmund (dieter@apple.com)
 * - created
 */

#include <net/multicast_list.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <net/if_dl.h>

__private_extern__ void
multicast_list_init(struct multicast_list * mc_list)
{
    SLIST_INIT(mc_list);
    return;
}

/*
 * Function: multicast_list_remove
 * Purpose:
 *   Remove the given list of multicast addresses from the interface and from
 *   the multicast list structure.
 */
__private_extern__ int
multicast_list_remove(struct multicast_list * mc_list)
{
    int				error;
    struct multicast_entry *	mc;
    int				result = 0;

    while ((mc = SLIST_FIRST(mc_list)) != NULL) {
	error = ifnet_remove_multicast(mc->mc_ifma);
	if (error != 0) {
	    result = error;
	}
	SLIST_REMOVE_HEAD(mc_list, mc_entries);
	ifmaddr_release(mc->mc_ifma);
	FREE(mc, M_DEVBUF);
    }
    return (result);
}

/*
 * Function: multicast_list_program
 * Purpose:
 *   Program the multicast filter on "target_ifp" using the values from
 *   "source_ifp", and saving the result in "mc_list"
 *
 *   We build a new list of multicast addresses while programming the new list.
 *   If that completes successfully, we remove the old list, and return the 
 *   new list.
 *
 *   If it fails, we remove what we've added to the new list, and
 *   return an error.
 */
__private_extern__ int
multicast_list_program(struct multicast_list * mc_list,
		       struct ifnet * source_ifp,
		       struct ifnet * target_ifp)
{
    int				alen;
    int				error = 0;
    int				i;
    struct multicast_entry *	mc = NULL;
    struct multicast_list	new_mc_list;
    struct sockaddr_dl		source_sdl;
    ifmultiaddr_t *		source_multicast_list;
    struct sockaddr_dl		target_sdl;

    alen = target_ifp->if_addrlen;
    bzero((char *)&target_sdl, sizeof(target_sdl));
    target_sdl.sdl_len = sizeof(target_sdl);
    target_sdl.sdl_family = AF_LINK;
    target_sdl.sdl_type = target_ifp->if_type;
    target_sdl.sdl_alen = alen;
    target_sdl.sdl_index = target_ifp->if_index;

    /* build a new list */
    multicast_list_init(&new_mc_list);
    error = ifnet_get_multicast_list(source_ifp, &source_multicast_list);
    if (error != 0) {
	printf("multicast_list_program: "
	       "ifnet_get_multicast_list(%s%d) failed, %d\n",
	       source_ifp->if_name, source_ifp->if_unit, error);
	return (error);
    }
    for (i = 0; source_multicast_list[i] != NULL; i++) {
	if (ifmaddr_address(source_multicast_list[i], 
			    (struct sockaddr *)&source_sdl, 
			    sizeof(source_sdl)) != 0
	    || source_sdl.sdl_family != AF_LINK) {
	    continue;
	}
	mc = _MALLOC(sizeof(struct multicast_entry), M_DEVBUF, M_WAITOK);
	if (mc == NULL) {
		error = ENOBUFS;
		break;
	}
	bcopy(LLADDR(&source_sdl), LLADDR(&target_sdl), alen);
	error = ifnet_add_multicast(target_ifp, (struct sockaddr *)&target_sdl, 
				    &mc->mc_ifma);
	if (error != 0) {
	    FREE(mc, M_DEVBUF);
	    break;
	}
	SLIST_INSERT_HEAD(&new_mc_list, mc, mc_entries);
    }
    if (error != 0) {
	/* restore previous state */
	(void)multicast_list_remove(&new_mc_list);
    } else {
	/* remove the old entries, and return the new list */
	(void)multicast_list_remove(mc_list);
	*mc_list = new_mc_list;
    }
    return (error);
}
