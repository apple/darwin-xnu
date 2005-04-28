/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

#define __KPI__
//#include <sys/kpi_interface.h>

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <kern/debug.h>
#include <libkern/OSAtomic.h>
#include <kern/kalloc.h>
#include <string.h>

void mbuf_tag_id_first_last(u_long *first, u_long *last);
errno_t mbuf_tag_id_find_internal(const char *string, u_long *out_id, int create);

static const mbuf_flags_t mbuf_flags_mask = MBUF_EXT | MBUF_PKTHDR | MBUF_EOR |
				MBUF_BCAST | MBUF_MCAST | MBUF_FRAG | MBUF_FIRSTFRAG |
				MBUF_LASTFRAG | MBUF_PROMISC;

void* mbuf_data(mbuf_t mbuf)
{
	return m_mtod(mbuf);
}

void* mbuf_datastart(mbuf_t mbuf)
{
	if (mbuf->m_flags & M_EXT)
		return mbuf->m_ext.ext_buf;
	if (mbuf->m_flags & M_PKTHDR)
		return mbuf->m_pktdat;
	return mbuf->m_dat;
}

errno_t mbuf_setdata(mbuf_t mbuf, void* data, size_t len)
{
	size_t	start = (size_t)((char*)mbuf_datastart(mbuf));
	size_t	maxlen = mbuf_maxlen(mbuf);
	
	if ((size_t)data < start || ((size_t)data) + len > start + maxlen)
		return EINVAL;
	mbuf->m_data = data;
	mbuf->m_len = len;
	
	return 0;
}

errno_t mbuf_align_32(mbuf_t mbuf, size_t len)
{
	if ((mbuf->m_flags & M_EXT) != 0 && m_mclhasreference(mbuf))
		return ENOTSUP;
	mbuf->m_data = mbuf_datastart(mbuf);
	mbuf->m_data += ((mbuf_trailingspace(mbuf) - len) &~ (sizeof(u_int32_t) - 1));
	
	return 0;
}

addr64_t mbuf_data_to_physical(void* ptr)
{
	return (addr64_t)mcl_to_paddr(ptr);
}

errno_t mbuf_get(mbuf_how_t how, mbuf_type_t type, mbuf_t *mbuf)
{
	/* Must set *mbuf to NULL in failure case */
	*mbuf = m_get(how, type);
	
	return (*mbuf == NULL) ? ENOMEM : 0;
}

errno_t mbuf_gethdr(mbuf_how_t how, mbuf_type_t type, mbuf_t *mbuf)
{
	/* Must set *mbuf to NULL in failure case */
	*mbuf = m_gethdr(how, type);
	
	return (*mbuf == NULL) ? ENOMEM : 0;
}

extern struct mbuf * m_mbigget(struct mbuf *m, int nowait);

errno_t mbuf_getcluster(mbuf_how_t how, mbuf_type_t type, size_t size, mbuf_t* mbuf)
{
	/* Must set *mbuf to NULL in failure case */
	errno_t	error = 0;
	int		created = 0;

	if (mbuf == NULL)
		return EINVAL;
	if (*mbuf == NULL) {
		*mbuf = m_get(how, type);
		if (*mbuf == NULL)
			return ENOMEM;
		created = 1;
	}
	/*
	 * At the time this code was written, m_mclget and m_mbigget would always
	 * return the same value that was passed in to it.
	 */
	if (size == MCLBYTES) {
		*mbuf = m_mclget(*mbuf, how);
	} else if (size == NBPG) {
		*mbuf = m_mbigget(*mbuf, how);
	} else {
		error = EINVAL;
		goto out;
	}
	if (*mbuf == NULL || ((*mbuf)->m_flags & M_EXT) == 0)
		error = ENOMEM;
out:
	if (created && error != 0) {
		error = ENOMEM;
		mbuf_free(*mbuf);
		*mbuf = NULL;
	}
	return error;	
}

errno_t mbuf_mclget(mbuf_how_t how, mbuf_type_t type, mbuf_t *mbuf)
{
	/* Must set *mbuf to NULL in failure case */
	errno_t	error = 0;
	int		created = 0;
	if (mbuf == NULL) return EINVAL;
	if (*mbuf == NULL) {
		error = mbuf_get(how, type, mbuf);
		if (error)
			return error;
		created = 1;
	}
	
	/*
	 * At the time this code was written, m_mclget would always
	 * return the same value that was passed in to it.
	 */
	*mbuf = m_mclget(*mbuf, how);
	
	if (created && ((*mbuf)->m_flags & M_EXT) == 0) {
		mbuf_free(*mbuf);
		*mbuf = NULL;
	}
	if (*mbuf == NULL || ((*mbuf)->m_flags & M_EXT) == 0)
		error = ENOMEM;
	return error;	
}


errno_t mbuf_getpacket(mbuf_how_t how, mbuf_t *mbuf)
{
	/* Must set *mbuf to NULL in failure case */
	errno_t	error = 0;
	
	*mbuf = m_getpacket_how(how);
	
	if (*mbuf == NULL) {
		if (how == MBUF_WAITOK)
			error = ENOMEM;
		else
			error = EWOULDBLOCK;
	}
	
	return error;
}

mbuf_t mbuf_free(mbuf_t mbuf)
{
	return m_free(mbuf);
}

void mbuf_freem(mbuf_t mbuf)
{
	m_freem(mbuf);
}

int	mbuf_freem_list(mbuf_t mbuf)
{
	return m_freem_list(mbuf);
}

size_t mbuf_leadingspace(mbuf_t mbuf)
{
	return m_leadingspace(mbuf);
}

size_t mbuf_trailingspace(mbuf_t mbuf)
{
	return m_trailingspace(mbuf);
}

/* Manipulation */
errno_t mbuf_copym(mbuf_t src, size_t offset, size_t len,
				   mbuf_how_t how, mbuf_t *new_mbuf)
{
	/* Must set *mbuf to NULL in failure case */
	*new_mbuf = m_copym(src, offset, len, how);
	
	return (*new_mbuf == NULL) ? ENOMEM : 0;
}

errno_t	mbuf_dup(mbuf_t src, mbuf_how_t how, mbuf_t *new_mbuf)
{
	/* Must set *new_mbuf to NULL in failure case */
	*new_mbuf = m_dup(src, how);
	
	return (*new_mbuf == NULL) ? ENOMEM : 0;
}

errno_t mbuf_prepend(mbuf_t *orig, size_t len, mbuf_how_t how)
{
	/* Must set *orig to NULL in failure case */
	*orig = m_prepend_2(*orig, len, how);
	
	return (*orig == NULL) ? ENOMEM : 0;
}

errno_t mbuf_split(mbuf_t src, size_t offset,
					mbuf_how_t how, mbuf_t *new_mbuf)
{
	/* Must set *new_mbuf to NULL in failure case */
	*new_mbuf = m_split(src, offset, how);
	
	return (*new_mbuf == NULL) ? ENOMEM : 0;
}

errno_t mbuf_pullup(mbuf_t *mbuf, size_t len)
{
	/* Must set *mbuf to NULL in failure case */
	*mbuf = m_pullup(*mbuf, len);
	
	return (*mbuf == NULL) ? ENOMEM : 0;
}

errno_t mbuf_pulldown(mbuf_t src, size_t *offset, size_t len, mbuf_t *location)
{
	/* Must set *location to NULL in failure case */
	int new_offset;
	*location = m_pulldown(src, *offset, len, &new_offset);
	*offset = new_offset;
	
	return (*location == NULL) ? ENOMEM : 0;
}

void mbuf_adj(mbuf_t mbuf, int len)
{
	m_adj(mbuf, len);
}

errno_t mbuf_copydata(mbuf_t m, size_t off, size_t len, void* out_data)
{
	/* Copied m_copydata, added error handling (don't just panic) */
	int count;

	while (off > 0) {
		if (m == 0)
			return EINVAL;
		if (off < (size_t)m->m_len)
			break;
		off -= m->m_len;
		m = m->m_next;
	}
	while (len > 0) {
		if (m == 0)
			return EINVAL;
		count = m->m_len - off > len ? len : m->m_len - off;
		bcopy(mtod(m, caddr_t) + off, out_data, count);
		len -= count;
		out_data = ((char*)out_data) + count;
		off = 0;
		m = m->m_next;
	}
	
	return 0;
}

int mbuf_mclref(mbuf_t mbuf)
{
	return m_mclref(mbuf);
}

int mbuf_mclunref(mbuf_t mbuf)
{
	return m_mclunref(mbuf);
}

int mbuf_mclhasreference(mbuf_t mbuf)
{
	if ((mbuf->m_flags & M_EXT))
		return m_mclhasreference(mbuf);
	else
		return 0;
}


/* mbuf header */
mbuf_t mbuf_next(mbuf_t mbuf)
{
	return mbuf->m_next;
}

errno_t mbuf_setnext(mbuf_t mbuf, mbuf_t next)
{
	if (next && ((next)->m_nextpkt != NULL ||
		(next)->m_type == MT_FREE)) return EINVAL;
	mbuf->m_next = next;
	
	return 0;
}

mbuf_t mbuf_nextpkt(mbuf_t mbuf)
{
	return mbuf->m_nextpkt;
}

void mbuf_setnextpkt(mbuf_t mbuf, mbuf_t nextpkt)
{
	mbuf->m_nextpkt = nextpkt;
}

size_t mbuf_len(mbuf_t mbuf)
{
	return mbuf->m_len;
}

void mbuf_setlen(mbuf_t mbuf, size_t len)
{
	mbuf->m_len = len;
}

size_t mbuf_maxlen(mbuf_t mbuf)
{
	if (mbuf->m_flags & M_EXT)
		return mbuf->m_ext.ext_size;
	return &mbuf->m_dat[MLEN] - ((char*)mbuf_datastart(mbuf));
}

mbuf_type_t mbuf_type(mbuf_t mbuf)
{
	return mbuf->m_type;
}

errno_t mbuf_settype(mbuf_t mbuf, mbuf_type_t new_type)
{
	if (new_type == MBUF_TYPE_FREE) return EINVAL;
	
	m_mchtype(mbuf, new_type);
	
	return 0;
}

mbuf_flags_t mbuf_flags(mbuf_t mbuf)
{
	return mbuf->m_flags & mbuf_flags_mask;
}

errno_t mbuf_setflags(mbuf_t mbuf, mbuf_flags_t flags)
{
	if ((flags & ~mbuf_flags_mask) != 0) return EINVAL;
	mbuf->m_flags = flags |
		(mbuf->m_flags & ~mbuf_flags_mask);
	
	return 0;
}

errno_t mbuf_setflags_mask(mbuf_t mbuf, mbuf_flags_t flags, mbuf_flags_t mask)
{
	if (((flags | mask) & ~mbuf_flags_mask) != 0) return EINVAL;
	
	mbuf->m_flags = (flags & mask) | (mbuf->m_flags & ~mask);
	
	return 0;
}

errno_t mbuf_copy_pkthdr(mbuf_t dest, mbuf_t src)
{
	if (((src)->m_flags & M_PKTHDR) == 0)
		return EINVAL;
	
	m_copy_pkthdr(dest, src);
	
	return 0;
}

size_t mbuf_pkthdr_len(mbuf_t mbuf)
{
	return mbuf->m_pkthdr.len;
}

void mbuf_pkthdr_setlen(mbuf_t mbuf, size_t len)
{
	mbuf->m_pkthdr.len = len;
}

ifnet_t mbuf_pkthdr_rcvif(mbuf_t mbuf)
{
	// If we reference count ifnets, we should take a reference here before returning
	return mbuf->m_pkthdr.rcvif;
}

errno_t mbuf_pkthdr_setrcvif(mbuf_t mbuf, ifnet_t ifnet)
{
	/* May want to walk ifnet list to determine if interface is valid */
	mbuf->m_pkthdr.rcvif = (struct ifnet*)ifnet;
	return 0;
}

void* mbuf_pkthdr_header(mbuf_t mbuf)
{
	return mbuf->m_pkthdr.header;
}

void mbuf_pkthdr_setheader(mbuf_t mbuf, void *header)
{
	mbuf->m_pkthdr.header = (void*)header;
}

/* mbuf aux data */
errno_t mbuf_aux_add(mbuf_t mbuf, int family, mbuf_type_t type, mbuf_t *aux_mbuf)
{
	*aux_mbuf = m_aux_add(mbuf, family, type);
	return (*aux_mbuf == NULL) ? ENOMEM : 0;
}

mbuf_t mbuf_aux_find(mbuf_t mbuf, int family, mbuf_type_t type)
{
	return m_aux_find(mbuf, family, type);
}

void mbuf_aux_delete(mbuf_t mbuf, mbuf_t aux)
{
	m_aux_delete(mbuf, aux);
}

void
mbuf_inbound_modified(mbuf_t mbuf)
{
	/* Invalidate hardware generated checksum flags */
	mbuf->m_pkthdr.csum_flags = 0;
}

extern void in_cksum_offset(struct mbuf* m, size_t ip_offset);
extern void in_delayed_cksum_offset(struct mbuf *m, int ip_offset);

void
mbuf_outbound_finalize(mbuf_t mbuf, u_long protocol_family, size_t protocol_offset)
{
	if ((mbuf->m_pkthdr.csum_flags & (CSUM_DELAY_DATA | CSUM_DELAY_IP)) == 0)
		return;
	
	/* Generate the packet in software, client needs it */
	switch (protocol_family) {
		case PF_INET:
			if (mbuf->m_pkthdr.csum_flags & CSUM_DELAY_DATA) {
				in_delayed_cksum_offset(mbuf, protocol_offset);
			}
			
			if (mbuf->m_pkthdr.csum_flags & CSUM_DELAY_IP) {
				in_cksum_offset(mbuf, protocol_offset);
			}
			
			mbuf->m_pkthdr.csum_flags &= ~(CSUM_DELAY_DATA | CSUM_DELAY_IP);
			break;
	
		default:
			/*
			 * Not sure what to do here if anything.
			 * Hardware checksum code looked pretty IPv4 specific.
			 */
			if ((mbuf->m_pkthdr.csum_flags & (CSUM_DELAY_DATA | CSUM_DELAY_IP)) != 0)
				panic("mbuf_outbound_finalize - CSUM flags set for non-IPv4 packet (%d)!\n", protocol_family);
	}
}

errno_t
mbuf_set_vlan_tag(
	mbuf_t mbuf,
	u_int16_t vlan)
{
	mbuf->m_pkthdr.csum_flags |= CSUM_VLAN_TAG_VALID;
	mbuf->m_pkthdr.vlan_tag = vlan;
	
	return 0;
}

errno_t
mbuf_get_vlan_tag(
	mbuf_t mbuf,
	u_int16_t *vlan)
{
	if ((mbuf->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) == 0)
		return ENXIO; // No vlan tag set
	
	*vlan = mbuf->m_pkthdr.vlan_tag;
	
	return 0;
}

errno_t
mbuf_clear_vlan_tag(
	mbuf_t mbuf)
{
	mbuf->m_pkthdr.csum_flags &= ~CSUM_VLAN_TAG_VALID;
	mbuf->m_pkthdr.vlan_tag = 0;
	
	return 0;
}

static const mbuf_csum_request_flags_t mbuf_valid_csum_request_flags = 
	MBUF_CSUM_REQ_IP | MBUF_CSUM_REQ_TCP | MBUF_CSUM_REQ_UDP | MBUF_CSUM_REQ_SUM16;

errno_t
mbuf_set_csum_requested(
	mbuf_t mbuf,
	mbuf_csum_request_flags_t request,
	u_int32_t value)
{
	request &= mbuf_valid_csum_request_flags;
	mbuf->m_pkthdr.csum_flags = (mbuf->m_pkthdr.csum_flags & 0xffff0000) | request;
	mbuf->m_pkthdr.csum_data = value;
	
	return 0;
}

errno_t
mbuf_get_csum_requested(
	mbuf_t mbuf,
	mbuf_csum_request_flags_t *request,
	u_int32_t *value)
{
	*request = mbuf->m_pkthdr.csum_flags;
	*request &= mbuf_valid_csum_request_flags;
	if (value != NULL) {
		*value = mbuf->m_pkthdr.csum_data;
	}
	
	return 0;
}

errno_t
mbuf_clear_csum_requested(
	mbuf_t mbuf)
{
	mbuf->m_pkthdr.csum_flags &= 0xffff0000;
	mbuf->m_pkthdr.csum_data = 0;
	
	return 0;
}

static const mbuf_csum_performed_flags_t mbuf_valid_csum_performed_flags = 
	MBUF_CSUM_DID_IP | MBUF_CSUM_IP_GOOD | MBUF_CSUM_DID_DATA |
	MBUF_CSUM_PSEUDO_HDR | MBUF_CSUM_TCP_SUM16;

errno_t
mbuf_set_csum_performed(
	mbuf_t mbuf,
	mbuf_csum_performed_flags_t performed,
	u_int32_t value)
{
	performed &= mbuf_valid_csum_performed_flags;
	mbuf->m_pkthdr.csum_flags = (mbuf->m_pkthdr.csum_flags & 0xffff0000) | performed;
	mbuf->m_pkthdr.csum_data = value;
	
	return 0;
}

errno_t
mbuf_get_csum_performed(
	mbuf_t mbuf,
	mbuf_csum_performed_flags_t *performed,
	u_int32_t *value)
{
	*performed = mbuf->m_pkthdr.csum_flags & mbuf_valid_csum_performed_flags;
	*value = mbuf->m_pkthdr.csum_data;
	
	return 0;
}

errno_t
mbuf_clear_csum_performed(
	mbuf_t mbuf)
{
	mbuf->m_pkthdr.csum_flags &= 0xffff0000;
	mbuf->m_pkthdr.csum_data = 0;
	
	return 0;
}

/*
 * Mbuf tag KPIs
 */

struct mbuf_tag_id_entry {
	SLIST_ENTRY(mbuf_tag_id_entry)	next;
	mbuf_tag_id_t					id;
	char							string[];
};

#define	MBUF_TAG_ID_ENTRY_SIZE(__str) \
	((size_t)&(((struct mbuf_tag_id_entry*)0)->string[0]) + \
	 strlen(__str) + 1)

#define	MTAG_FIRST_ID					1000
static u_long							mtag_id_next = MTAG_FIRST_ID;
static SLIST_HEAD(,mbuf_tag_id_entry)	mtag_id_list = {NULL};
static lck_mtx_t						*mtag_id_lock = NULL;

__private_extern__ void
mbuf_tag_id_first_last(
	u_long	*first,
	u_long	*last)
{
	*first = MTAG_FIRST_ID;
	*last = mtag_id_next - 1;
}

__private_extern__ errno_t
mbuf_tag_id_find_internal(
	const char	*string,
	u_long		*out_id,
	int			create)
{
	struct mbuf_tag_id_entry				*entry = NULL;
	
	
	*out_id = 0;
	
	if (string == NULL || out_id == NULL) {
		return EINVAL;
	}
	
	/* Don't bother allocating the lock if we're only doing a lookup */
	if (create == 0 && mtag_id_lock == NULL)
		return ENOENT;
	
	/* Allocate lock if necessary */
	if (mtag_id_lock == NULL) {
		lck_grp_attr_t	*grp_attrib = NULL;
		lck_attr_t		*lck_attrb = NULL;
		lck_grp_t		*lck_group = NULL;
		lck_mtx_t		*new_lock = NULL;
		
		grp_attrib = lck_grp_attr_alloc_init();
		lck_grp_attr_setdefault(grp_attrib);
		lck_group = lck_grp_alloc_init("mbuf_tag_allocate_id", grp_attrib);
		lck_grp_attr_free(grp_attrib);
		lck_attrb = lck_attr_alloc_init();
		lck_attr_setdefault(lck_attrb);
		lck_attr_setdebug(lck_attrb);
		new_lock = lck_mtx_alloc_init(lck_group, lck_attrb);
		if (!OSCompareAndSwap((UInt32)0, (UInt32)new_lock, (UInt32*)&mtag_id_lock)) {
			/*
			 * If the atomic swap fails, someone else has already
			 * done this work. We can free the stuff we allocated.
			 */
			lck_mtx_free(new_lock, lck_group);
			lck_grp_free(lck_group);
		}
		lck_attr_free(lck_attrb);
	}
	
	/* Look for an existing entry */
	lck_mtx_lock(mtag_id_lock);
	SLIST_FOREACH(entry, &mtag_id_list, next) {
		if (strcmp(string, entry->string) == 0) {
			break;
		}
	}
	
	if (entry == NULL) {
		if (create == 0) {
			lck_mtx_unlock(mtag_id_lock);
			return ENOENT;
		}
		
		entry = kalloc(MBUF_TAG_ID_ENTRY_SIZE(string));
		if (entry == NULL) {
			lck_mtx_unlock(mtag_id_lock);
			return ENOMEM;
		}
		
		strcpy(entry->string, string);
		entry->id = mtag_id_next;
		mtag_id_next++;
		SLIST_INSERT_HEAD(&mtag_id_list, entry, next);
	}
	lck_mtx_unlock(mtag_id_lock);
	
	*out_id = entry->id;
	
	return 0;
}

errno_t
mbuf_tag_id_find(
	const char		*string,
	mbuf_tag_id_t	*out_id)
{
	return mbuf_tag_id_find_internal(string, (u_long*)out_id, 1);
}

errno_t
mbuf_tag_allocate(
	mbuf_t			mbuf,
	mbuf_tag_id_t	id,
	mbuf_tag_type_t	type,
	size_t			length,
	mbuf_how_t		how,
	void**			data_p)
{
	struct m_tag *tag;
	
	if (data_p != NULL)
		*data_p = NULL;
	
	/* Sanity check parameters */
	if (mbuf == NULL || (mbuf->m_flags & M_PKTHDR) == 0 || id < MTAG_FIRST_ID ||
		id >= mtag_id_next || length < 1 || (length & 0xffff0000) != 0 ||
		data_p == NULL) {
		return EINVAL;
	}
	
	/* Make sure this mtag hasn't already been allocated */
	tag = m_tag_locate(mbuf, id, type, NULL);
	if (tag != NULL) {
		return EEXIST;
	}
	
	/* Allocate an mtag */
	tag = m_tag_alloc(id, type, length, how);
	if (tag == NULL) {
		return how == M_WAITOK ? ENOMEM : EWOULDBLOCK;
	}
	
	/* Attach the mtag and set *data_p */
	m_tag_prepend(mbuf, tag);
	*data_p = tag + 1;
	
	return 0;
}

errno_t
mbuf_tag_find(
	mbuf_t			mbuf,
	mbuf_tag_id_t	id,
	mbuf_tag_type_t	type,
	size_t*			length,
	void**			data_p)
{
	struct m_tag *tag;
	
	if (length != NULL)
		*length = 0;
	if (data_p != NULL)
		*data_p = NULL;
	
	/* Sanity check parameters */
	if (mbuf == NULL || (mbuf->m_flags & M_PKTHDR) == 0 || id < MTAG_FIRST_ID ||
		id >= mtag_id_next || length == NULL || data_p == NULL) {
		return EINVAL;
	}
	
	/* Locate an mtag */
	tag = m_tag_locate(mbuf, id, type, NULL);
	if (tag == NULL) {
		return ENOENT;
	}
	
	/* Copy out the pointer to the data and the lenght value */
	*length = tag->m_tag_len;
	*data_p = tag + 1;
	
	return 0;
}

void
mbuf_tag_free(
	mbuf_t			mbuf,
	mbuf_tag_id_t	id,
	mbuf_tag_type_t	type)
{
	struct m_tag *tag;
	
	if (mbuf == NULL || (mbuf->m_flags & M_PKTHDR) == 0 || id < MTAG_FIRST_ID ||
		id >= mtag_id_next)
		return;
	
	tag = m_tag_locate(mbuf, id, type, NULL);
	if (tag == NULL) {
		return;
	}
	
	m_tag_delete(mbuf, tag);
	return;
}

/* mbuf stats */
void mbuf_stats(struct mbuf_stat *stats)
{
	stats->mbufs = mbstat.m_mbufs;
	stats->clusters = mbstat.m_clusters;
	stats->clfree = mbstat.m_clfree;
	stats->drops = mbstat.m_drops;
	stats->wait = mbstat.m_wait;
	stats->drain = mbstat.m_drain;
	__builtin_memcpy(stats->mtypes, mbstat.m_mtypes, sizeof(stats->mtypes));
	stats->mcfail = mbstat.m_mcfail;
	stats->mpfail = mbstat.m_mpfail;
	stats->msize = mbstat.m_msize;
	stats->mclbytes = mbstat.m_mclbytes;
	stats->minclsize = mbstat.m_minclsize;
	stats->mlen = mbstat.m_mlen;
	stats->mhlen = mbstat.m_mhlen;
	stats->bigclusters = mbstat.m_bigclusters;
	stats->bigclfree = mbstat.m_bigclfree;
	stats->bigmclbytes = mbstat.m_bigmclbytes;
}

errno_t
mbuf_allocpacket(mbuf_how_t how, size_t packetlen, unsigned int *maxchunks, mbuf_t *mbuf)
{
	errno_t error;
	struct mbuf *m;
	unsigned int numpkts = 1;
	unsigned int numchunks = maxchunks ? *maxchunks : 0;

	if (packetlen == 0) {
		error = EINVAL;
		goto out;
	}
	m = m_allocpacket_internal(&numpkts, packetlen, maxchunks ? &numchunks : NULL, how, 1, 0);
	if (m == 0) {
		if (maxchunks && *maxchunks && numchunks > *maxchunks)
			error = ENOBUFS;
		else
			error = ENOMEM;
	} else {
		error = 0;
		*mbuf = m;
	}
out:
	return error;
}


/*
 * mbuf_copyback differs from m_copyback in a few ways:
 * 1) mbuf_copyback will allocate clusters for new mbufs we append
 * 2) mbuf_copyback will grow the last mbuf in the chain if possible
 * 3) mbuf_copyback reports whether or not the operation succeeded
 * 4) mbuf_copyback allows the caller to specify M_WAITOK or M_NOWAIT
 */
errno_t
mbuf_copyback(
	mbuf_t		m,
	size_t		off,
	size_t		len,
	const void	*data,
	mbuf_how_t	how)
{
	size_t	mlen;
	mbuf_t	m_start = m;
	mbuf_t	n;
	int		totlen = 0;
	errno_t		result = 0;
	const char	*cp = data;

	if (m == NULL || len == 0 || data == NULL)
		return EINVAL;
	
	while (off > (mlen = m->m_len)) {
		off -= mlen;
		totlen += mlen;
		if (m->m_next == 0) {
			n = m_getclr(how, m->m_type);
			if (n == 0) {
				result = ENOBUFS;
				goto out;
			}
			n->m_len = MIN(MLEN, len + off);
			m->m_next = n;
		}
		m = m->m_next;
	}
	
	while (len > 0) {
		mlen = MIN(m->m_len - off, len);
		if (mlen < len && m->m_next == NULL && mbuf_trailingspace(m) > 0) {
			size_t	grow = MIN(mbuf_trailingspace(m), len - mlen);
			mlen += grow;
			m->m_len += grow;
		}
		bcopy(cp, off + (char*)mbuf_data(m), (unsigned)mlen);
		cp += mlen;
		len -= mlen;
		mlen += off;
		off = 0;
		totlen += mlen;
		if (len == 0)
			break;
		if (m->m_next == 0) {
			n = m_get(how, m->m_type);
			if (n == NULL) {
				result = ENOBUFS;
				goto out;
			}
			if (len > MINCLSIZE) {
				/* cluter allocation failure is okay, we can grow chain */
				mbuf_mclget(how, m->m_type, &n);
			}
			n->m_len = MIN(mbuf_maxlen(n), len);
			m->m_next = n;
		}
		m = m->m_next;
	}
	
out:
	if ((m_start->m_flags & M_PKTHDR) && (m_start->m_pkthdr.len < totlen))
		m_start->m_pkthdr.len = totlen;
	
	return result;
}
