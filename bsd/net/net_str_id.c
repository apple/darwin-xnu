/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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

#include <sys/types.h>
#include <kern/locks.h>
#include <kern/kalloc.h>
#include <sys/errno.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <libkern/OSAtomic.h>
#include <libkern/libkern.h>
#include <net/if.h>
#include <net/if_mib.h>
#include <string.h>

#include "net/net_str_id.h"

#define	NET_ID_STR_ENTRY_SIZE(__str) \
	((size_t)&(((struct net_str_id_entry*)0)->nsi_string[0]) + \
	strlen(__str) + 1)

#define	FIRST_NET_STR_ID				1000
static SLIST_HEAD(,net_str_id_entry)	net_str_id_list = {NULL};
static lck_mtx_t						*net_str_id_lock = NULL;

static u_int32_t nsi_kind_next[NSI_MAX_KIND] = { FIRST_NET_STR_ID, FIRST_NET_STR_ID, FIRST_NET_STR_ID };
static u_int32_t nsi_next_id = FIRST_NET_STR_ID;

#if NETMIBS

extern int sysctl_if_family_ids SYSCTL_HANDLER_ARGS;

SYSCTL_DECL(_net_link_generic_system);

SYSCTL_PROC(_net_link_generic_system, OID_AUTO, if_family_ids, CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
	0, 0, sysctl_if_family_ids, "S, if_family_id", "Interface Family ID table");

#endif /* NETMIBS */


__private_extern__ void
net_str_id_init(void)
{
	lck_grp_attr_t	*grp_attrib = NULL;
	lck_attr_t		*lck_attrb = NULL;
	lck_grp_t		*lck_group = NULL;
	
	grp_attrib = lck_grp_attr_alloc_init();
	lck_group = lck_grp_alloc_init("mbuf_tag_allocate_id", grp_attrib);
	lck_grp_attr_free(grp_attrib);
	lck_attrb = lck_attr_alloc_init();
	
	net_str_id_lock = lck_mtx_alloc_init(lck_group, lck_attrb);
	
	lck_grp_free(lck_group);
	lck_attr_free(lck_attrb);
}

__private_extern__ void
net_str_id_first_last(u_int32_t *first, u_int32_t *last, u_int32_t kind)
{
	*first = FIRST_NET_STR_ID;

	switch (kind) {
		case NSI_MBUF_TAG:
		case NSI_VENDOR_CODE:
		case NSI_IF_FAM_ID:
			*last = nsi_kind_next[kind] - 1;
			break;
		default:
			*last = FIRST_NET_STR_ID - 1;
			break;
	}
}

__private_extern__ errno_t
net_str_id_find_internal(const char	*string, u_int32_t *out_id,
						  u_int32_t	kind, int create)
{
	struct net_str_id_entry			*entry = NULL;
	
	
	if (string == NULL || out_id == NULL || kind >= NSI_MAX_KIND)
		return EINVAL;

	*out_id = 0;
	
	/* Look for an existing entry */
	lck_mtx_lock(net_str_id_lock);
	SLIST_FOREACH(entry, &net_str_id_list, nsi_next) {
		if (strcmp(string, entry->nsi_string) == 0) {
			break;
		}
	}
	
	if (entry == NULL) {
		if (create == 0) {
			lck_mtx_unlock(net_str_id_lock);
			return ENOENT;
		}
		
		entry = kalloc(NET_ID_STR_ENTRY_SIZE(string));
		if (entry == NULL) {
			lck_mtx_unlock(net_str_id_lock);
			return ENOMEM;
		}
		
		strlcpy(entry->nsi_string, string, strlen(string) + 1);
		entry->nsi_flags = (1 << kind);
		entry->nsi_id = nsi_next_id++;
		nsi_kind_next[kind] = nsi_next_id;
		SLIST_INSERT_HEAD(&net_str_id_list, entry, nsi_next);
	} else if ((entry->nsi_flags & (1 << kind)) == 0) {
		if (create == 0) {
			lck_mtx_unlock(net_str_id_lock);
			return ENOENT;
		}
		entry->nsi_flags |= (1 << kind);
		if (entry->nsi_id >= nsi_kind_next[kind])
			nsi_kind_next[kind] = entry->nsi_id + 1;
	}
	lck_mtx_unlock(net_str_id_lock);

	*out_id = entry->nsi_id;
	
	return 0;
}


#if NETMIBS

#define ROUNDUP32(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

int
sysctl_if_family_ids SYSCTL_HANDLER_ARGS /* XXX bad syntax! */
{
#pragma unused(oidp)
#pragma unused(arg1)
#pragma unused(arg2)
	errno_t	error = 0;
	struct net_str_id_entry *entry = NULL;
	struct if_family_id *iffmid = NULL;
	size_t max_size = 0;
	
	lck_mtx_lock(net_str_id_lock);
	SLIST_FOREACH(entry, &net_str_id_list, nsi_next) {
		size_t str_size;
		size_t iffmid_size;
		
		if ((entry->nsi_flags & (1 << NSI_IF_FAM_ID)) == 0)
			continue;
		
		str_size = strlen(entry->nsi_string) + 1;
		iffmid_size = ROUNDUP32(offsetof(struct net_str_id_entry, nsi_string) + str_size);

		if (iffmid_size > max_size) {
			if (iffmid) 
				_FREE(iffmid, M_TEMP);
			iffmid = _MALLOC(iffmid_size, M_TEMP, M_WAITOK);
			if (iffmid == NULL) {
				lck_mtx_unlock(net_str_id_lock);
				error = ENOMEM;
				goto done;
			}
			max_size = iffmid_size;
		}

		bzero(iffmid, iffmid_size);
		iffmid->iffmid_len = iffmid_size;
		iffmid->iffmid_id = entry->nsi_id;
		strlcpy(iffmid->iffmid_str, entry->nsi_string, str_size);
        error = SYSCTL_OUT(req, iffmid, iffmid_size);
        if (error) {
			lck_mtx_unlock(net_str_id_lock);
			goto done;
        }
		
	}
	lck_mtx_unlock(net_str_id_lock);
	
done:
	if (iffmid) 
		_FREE(iffmid, M_TEMP);
	return error;
}

#endif /* NETMIBS */

