/*
 * Copyright (c) 2016-2017 Apple Inc. All rights reserved.
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

#include <sys/cdefs.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mcache.h>
#include <kern/kern_types.h>
#include <net/pf_pbuf.h>
#include <netinet/in.h>

void
pbuf_init_mbuf(pbuf_t *pbuf, struct mbuf *m, struct ifnet *ifp)
{

	VERIFY((m->m_flags & M_PKTHDR) != 0);

	pbuf->pb_type = PBUF_TYPE_MBUF;
	pbuf->pb_mbuf = m;
	pbuf->pb_ifp = ifp;
	pbuf->pb_next = NULL;
	pbuf_sync(pbuf);
}

void
pbuf_init_memory(pbuf_t *pbuf, const struct pbuf_memory *mp, struct ifnet *ifp)
{

	pbuf->pb_type = PBUF_TYPE_MEMORY;
	pbuf->pb_memory = *mp;
	pbuf->pb_ifp = ifp;
	pbuf->pb_next = NULL;
	pbuf_sync(pbuf);
}

void
pbuf_destroy(pbuf_t *pbuf)
{

	if (pbuf->pb_type == PBUF_TYPE_MBUF) {
		if (pbuf->pb_mbuf) {
			m_freem(pbuf->pb_mbuf);
			pbuf->pb_mbuf = NULL;
		}
	} else
	if (pbuf->pb_type == PBUF_TYPE_MEMORY) {
		VERIFY(pbuf->pb_memory.pm_buffer != NULL);
		(void) (pbuf->pb_memory.pm_action)(&pbuf->pb_memory,
		    PBUF_ACTION_DESTROY);
	} else {
		VERIFY(pbuf->pb_type == PBUF_TYPE_ZOMBIE);
	}

	memset(pbuf, 0, sizeof(*pbuf));
}

void
pbuf_sync(pbuf_t *pbuf)
{

	if (pbuf->pb_type == PBUF_TYPE_MBUF) {
		struct mbuf *m = pbuf->pb_mbuf;

		VERIFY(m != NULL);
		VERIFY(m->m_flags & M_PKTHDR);

		pbuf->pb_data = mtod(m, void *);
		pbuf->pb_packet_len = m->m_pkthdr.len;
		pbuf->pb_contig_len = m->m_len;
		pbuf->pb_csum_flags = &m->m_pkthdr.csum_flags;
		pbuf->pb_csum_data = &m->m_pkthdr.csum_data;
		pbuf->pb_proto = &m->m_pkthdr.pkt_proto;
		pbuf->pb_flowsrc = &m->m_pkthdr.pkt_flowsrc;
		pbuf->pb_flowid = &m->m_pkthdr.pkt_flowid;
		pbuf->pb_flags = &m->m_pkthdr.pkt_flags;
		pbuf->pb_pftag = m_pftag(m);
	} else
	if (pbuf->pb_type == PBUF_TYPE_MEMORY) {
		struct pbuf_memory *nm = &pbuf->pb_memory;

		VERIFY(nm->pm_buffer != NULL);
		VERIFY(nm->pm_buffer_len != 0);
		VERIFY(nm->pm_len != 0);
		VERIFY(nm->pm_len <= nm->pm_buffer_len);
		VERIFY(nm->pm_offset < nm->pm_len);

		pbuf->pb_data = &nm->pm_buffer[nm->pm_offset];
		pbuf->pb_packet_len = nm->pm_len;
		pbuf->pb_contig_len = nm->pm_len;
		pbuf->pb_csum_flags = &nm->pm_csum_flags;
		pbuf->pb_csum_data = &nm->pm_csum_data;
		pbuf->pb_proto = &nm->pm_proto;
		pbuf->pb_flowsrc = &nm->pm_flowsrc;
		pbuf->pb_flowid = &nm->pm_flowid;
		pbuf->pb_flags = &nm->pm_flags;
		pbuf->pb_pftag = &nm->pm_pftag;
	} else
		panic("%s: bad pb_type: %d", __func__, pbuf->pb_type);
}

struct mbuf *
pbuf_to_mbuf(pbuf_t *pbuf, boolean_t release_ptr)
{
	struct mbuf *m = NULL;

	pbuf_sync(pbuf);

	if (pbuf->pb_type == PBUF_TYPE_MBUF) {
		m = pbuf->pb_mbuf;
		if (release_ptr) {
			pbuf->pb_mbuf = NULL;
			pbuf_destroy(pbuf);
		}
	} else
	if (pbuf->pb_type == PBUF_TYPE_MEMORY) {
		if (pbuf->pb_packet_len > (u_int)MHLEN) {
			if (pbuf->pb_packet_len > (u_int)MCLBYTES) {
				printf("%s: packet too big for cluster (%u)\n",
				    __func__, pbuf->pb_packet_len);
				return (NULL);
			}
			m = m_getcl(M_WAITOK, MT_DATA, M_PKTHDR);
		} else {
			m = m_gethdr(M_DONTWAIT, MT_DATA);
		}
		if (m == NULL)
			return (NULL);

		m_copyback(m, 0, pbuf->pb_packet_len, pbuf->pb_data);
		m->m_pkthdr.csum_flags = *pbuf->pb_csum_flags;
		m->m_pkthdr.csum_data = *pbuf->pb_csum_data;
		m->m_pkthdr.pkt_proto = *pbuf->pb_proto;
		m->m_pkthdr.pkt_flowsrc = *pbuf->pb_flowsrc;
		m->m_pkthdr.pkt_flowid = *pbuf->pb_flowid;
		m->m_pkthdr.pkt_flags = *pbuf->pb_flags;

		if (pbuf->pb_pftag != NULL) {
			struct pf_mtag *pftag = m_pftag(m);

			if (pftag != NULL)
				*pftag = *pbuf->pb_pftag;
		}

		if (release_ptr)
			pbuf_destroy(pbuf);
	}

	return (m);
}

struct mbuf *
pbuf_clone_to_mbuf(pbuf_t *pbuf)
{
	struct mbuf *m = NULL;

	pbuf_sync(pbuf);

	if (pbuf->pb_type == PBUF_TYPE_MBUF)
		m = m_copy(pbuf->pb_mbuf, 0, M_COPYALL);
	else
	if (pbuf->pb_type == PBUF_TYPE_MEMORY)
		m = pbuf_to_mbuf(pbuf, FALSE);
	else
		panic("%s: bad pb_type: %d", __func__, pbuf->pb_type);

	return (m);
}

void *
pbuf_ensure_writable(pbuf_t *pbuf, size_t len)
{

	if (pbuf->pb_type == PBUF_TYPE_MBUF) {
		struct mbuf *m = pbuf->pb_mbuf;

		if (m_makewritable(&pbuf->pb_mbuf, 0, len, M_DONTWAIT))
			return (NULL);

		if (pbuf->pb_mbuf == NULL) {
			pbuf_destroy(pbuf);
			return (NULL);
		}

		if  (m != pbuf->pb_mbuf)
			pbuf_sync(pbuf);

	} else
	if (pbuf->pb_type != PBUF_TYPE_MEMORY)
		panic("%s: bad pb_type: %d", __func__, pbuf->pb_type);

	return (pbuf->pb_data);
}

void *
pbuf_resize_segment(pbuf_t *pbuf, int off, int olen, int nlen)
{
	void *rv = NULL;

	VERIFY(off >= 0);
	VERIFY((u_int)off <= pbuf->pb_packet_len);

	if (pbuf->pb_type == PBUF_TYPE_MBUF) {
		struct mbuf *m, *n;

		VERIFY(pbuf->pb_mbuf != NULL);

		m = pbuf->pb_mbuf;

		if (off > 0) {
			/* Split the mbuf chain at the specified boundary */
			if ((n = m_split(m, off, M_DONTWAIT)) == NULL)
				return (NULL);
		} else {
			n = m;
		}

		/* Trim old length */
		m_adj(n, olen);

		/* Prepend new length */
		if (M_PREPEND(n, nlen, M_DONTWAIT, 0) == NULL)
			return (NULL);

		rv = mtod(n, void *);

		if (off > 0) {
			/* Merge the two chains */
			int mlen;

			mlen = n->m_pkthdr.len;
			m_cat(m, n);
			m->m_pkthdr.len += mlen;
		} else {
			/* The new mbuf becomes the packet header */
			pbuf->pb_mbuf = n;
		}

		pbuf_sync(pbuf);
	} else
	if (pbuf->pb_type == PBUF_TYPE_MEMORY) {
		struct pbuf_memory *nm = &pbuf->pb_memory;
		u_int true_offset, move_len;
		int delta_len;
		uint8_t *psrc, *pdst;

		delta_len = nlen - olen;
		VERIFY(nm->pm_offset + (nm->pm_len + delta_len) <=
		    nm->pm_buffer_len);

		true_offset = (u_int)off + nm->pm_offset;
		rv = &nm->pm_buffer[true_offset];
		psrc = &nm->pm_buffer[true_offset + (u_int)olen];
		pdst = &nm->pm_buffer[true_offset + (u_int)nlen];
		move_len = pbuf->pb_packet_len - ((u_int)off + olen);
		memmove(pdst, psrc, move_len);

		nm->pm_len += delta_len;

		VERIFY((nm->pm_len + nm->pm_offset) <= nm->pm_buffer_len);

		pbuf_sync(pbuf);
	} else
		panic("pbuf_csum_flags_get: bad pb_type: %d", pbuf->pb_type);

	return (rv);
}

void *
pbuf_contig_segment(pbuf_t *pbuf, int off, int len)
{
	void *rv = NULL;

	VERIFY(off >= 0);
	VERIFY(len >= 0);
	VERIFY((u_int)(off + len) < pbuf->pb_packet_len);

	/*
	 * Note: If this fails, then the pbuf is destroyed. This is a
	 * side-effect of m_pulldown().
	 *
	 * PF expects this behaviour so it's not a real problem.
	 */

	if (pbuf->pb_type == PBUF_TYPE_MBUF) {
		struct mbuf *n;
		int moff;

		n = m_pulldown(pbuf->pb_mbuf, off, len, &moff);
		if (n == NULL) {
			/* mbuf is freed by m_pulldown() in this case */
			pbuf->pb_mbuf = NULL;
			pbuf_destroy(pbuf);
			return (NULL);
		}

		pbuf_sync(pbuf);

		rv = (void *)(mtod(n, uint8_t *) + moff);
	} else
	if (pbuf->pb_type == PBUF_TYPE_MEMORY) {
		/*
		 * This always succeeds since memory pbufs are fully contig.
		 */
		rv = (void *)(uintptr_t)(((uint8_t *)pbuf->pb_data)[off]);
	} else
		panic("%s: bad pb_type: %d", __func__, pbuf->pb_type);

	return (rv);
}

void
pbuf_copy_back(pbuf_t *pbuf, int off, int len, void *src)
{

	VERIFY(off >= 0);
	VERIFY(len >= 0);
	VERIFY((u_int)(off + len) <= pbuf->pb_packet_len);

	if (pbuf->pb_type == PBUF_TYPE_MBUF)
		m_copyback(pbuf->pb_mbuf, off, len, src);
	else
	if (pbuf->pb_type == PBUF_TYPE_MBUF) {
		if (len)
			memcpy(&((uint8_t *)pbuf->pb_data)[off], src, len);
	} else
		panic("%s: bad pb_type: %d", __func__, pbuf->pb_type);
}

void
pbuf_copy_data(pbuf_t *pbuf, int off, int len, void *dst)
{

	VERIFY(off >= 0);
	VERIFY(len >= 0);
	VERIFY((u_int)(off + len) <= pbuf->pb_packet_len);

	if (pbuf->pb_type == PBUF_TYPE_MBUF)
		m_copydata(pbuf->pb_mbuf, off, len, dst);
	else
	if (pbuf->pb_type == PBUF_TYPE_MBUF) {
		if (len)
			memcpy(dst, &((uint8_t *)pbuf->pb_data)[off], len);
	} else
		panic("%s: bad pb_type: %d", __func__, pbuf->pb_type);
}

uint16_t
pbuf_inet_cksum(const pbuf_t *pbuf, uint32_t nxt, uint32_t off, uint32_t len)
{
	uint16_t sum = 0;

	if (pbuf->pb_type == PBUF_TYPE_MBUF)
		sum = inet_cksum(pbuf->pb_mbuf, nxt, off, len);
	else
	if (pbuf->pb_type == PBUF_TYPE_MEMORY)
		sum = inet_cksum_buffer(pbuf->pb_data, nxt, off, len);
	else
		panic("%s: bad pb_type: %d", __func__, pbuf->pb_type);

	return (sum);
}

uint16_t
pbuf_inet6_cksum(const pbuf_t *pbuf, uint32_t nxt, uint32_t off, uint32_t len)
{
	uint16_t sum = 0;

	if (pbuf->pb_type == PBUF_TYPE_MBUF)
		sum = inet6_cksum(pbuf->pb_mbuf, nxt, off, len);
	else
	if (pbuf->pb_type == PBUF_TYPE_MEMORY)
		sum = inet6_cksum_buffer(pbuf->pb_data, nxt, off, len);
	else
		panic("%s: bad pb_type: %d", __func__, pbuf->pb_type);

	return (sum);
}

mbuf_svc_class_t
pbuf_get_service_class(const pbuf_t *pbuf)
{

	if (pbuf->pb_type == PBUF_TYPE_MBUF)
		return m_get_service_class(pbuf->pb_mbuf);

	VERIFY(pbuf->pb_type == PBUF_TYPE_MEMORY);

	return (MBUF_SC_BE);
}
