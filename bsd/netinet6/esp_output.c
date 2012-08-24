/*
 * Copyright (c) 2008-2011 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/esp_output.c,v 1.1.2.3 2002/04/28 05:40:26 suz Exp $	*/
/*	$KAME: esp_output.c,v 1.44 2001/07/26 06:53:15 jinmei Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define _IP_VHL

/*
 * RFC1827/2406 Encapsulated Security Payload.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_var.h>
#include <netinet/udp.h> /* for nat traversal */

#if INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#endif

#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif
#include <netinet6/ah.h>
#if INET6
#include <netinet6/ah6.h>
#endif
#include <netinet6/esp.h>
#if INET6
#include <netinet6/esp6.h>
#endif
#include <netkey/key.h>
#include <netkey/keydb.h>

#include <net/net_osdep.h>

#include <sys/kdebug.h>
#define DBG_LAYER_BEG		NETDBG_CODE(DBG_NETIPSEC, 1)
#define DBG_LAYER_END		NETDBG_CODE(DBG_NETIPSEC, 3)
#define DBG_FNC_ESPOUT		NETDBG_CODE(DBG_NETIPSEC, (4 << 8))
#define DBG_FNC_ENCRYPT		NETDBG_CODE(DBG_NETIPSEC, (5 << 8))

static int esp_output(struct mbuf *, u_char *, struct mbuf *,
	int, struct secasvar *sav);

extern int	esp_udp_encap_port;
extern u_int32_t natt_now;

extern lck_mtx_t *sadb_mutex;

/*
 * compute ESP header size.
 */
size_t
esp_hdrsiz(isr)
	struct ipsecrequest *isr;
{

	/* sanity check */
	if (isr == NULL)
		panic("esp_hdrsiz: NULL was passed.\n");


#if 0
	lck_mtx_lock(sadb_mutex);
	{
		struct secasvar *sav;
		const struct esp_algorithm *algo;
		const struct ah_algorithm *aalgo;
		size_t ivlen;
		size_t authlen;
		size_t hdrsiz;
		size_t maxpad;
	
		/*%%%% this needs to change - no sav in ipsecrequest any more */
		sav = isr->sav;
	
		if (isr->saidx.proto != IPPROTO_ESP)
			panic("unsupported mode passed to esp_hdrsiz");
	
		if (sav == NULL)
			goto estimate;
		if (sav->state != SADB_SASTATE_MATURE
		 && sav->state != SADB_SASTATE_DYING)
			goto estimate;
	
		/* we need transport mode ESP. */
		algo = esp_algorithm_lookup(sav->alg_enc);
		if (!algo)
			goto estimate;
		ivlen = sav->ivlen;
		if (ivlen < 0)
			goto estimate;
	
		if (algo->padbound)
			maxpad = algo->padbound;
		else
			maxpad = 4;
		maxpad += 1; /* maximum 'extendsiz' is padbound + 1, see esp_output */
		
		if (sav->flags & SADB_X_EXT_OLD) {
			/* RFC 1827 */
			hdrsiz = sizeof(struct esp) + ivlen + maxpad;
		} else {
			/* RFC 2406 */
			aalgo = ah_algorithm_lookup(sav->alg_auth);
			if (aalgo && sav->replay && sav->key_auth)
				authlen = (aalgo->sumsiz)(sav);
			else
				authlen = 0;
			hdrsiz = sizeof(struct newesp) + ivlen + maxpad + authlen;
		}
		
		/*
		 * If the security association indicates that NATT is required,
		 * add the size of the NATT encapsulation header:
		 */
		if ((sav->flags & SADB_X_EXT_NATT) != 0) hdrsiz += sizeof(struct udphdr) + 4;
	
		lck_mtx_unlock(sadb_mutex);
		return hdrsiz;
	}
estimate:
   lck_mtx_unlock(sadb_mutex);
#endif
	/*
	 * ASSUMING:
	 *	sizeof(struct newesp) > sizeof(struct esp). (8)
	 *	esp_max_ivlen() = max ivlen for CBC mode
	 *	17 = (maximum padding length without random padding length)
	 *	   + (Pad Length field) + (Next Header field).
	 *	64 = maximum ICV we support.
	 *  sizeof(struct udphdr) in case NAT traversal is used
	 */
	return sizeof(struct newesp) + esp_max_ivlen() + 17 + AH_MAXSUMSIZE + sizeof(struct udphdr);
}

/*
 * Modify the packet so that the payload is encrypted.
 * The mbuf (m) must start with IPv4 or IPv6 header.
 * On failure, free the given mbuf and return NULL.
 *
 * on invocation:
 *	m   nexthdrp md
 *	v   v        v
 *	IP ......... payload
 * during the encryption:
 *	m   nexthdrp mprev md
 *	v   v        v     v
 *	IP ............... esp iv payload pad padlen nxthdr
 *	                   <--><-><------><--------------->
 *	                   esplen plen    extendsiz
 *	                       ivlen
 *	                   <-----> esphlen
 *	<-> hlen
 *	<-----------------> espoff
 */
static int
esp_output(m, nexthdrp, md, af, sav)
	struct mbuf *m;
	u_char *nexthdrp;
	struct mbuf *md;
	int af;
	struct secasvar *sav;
{
	struct mbuf *n;
	struct mbuf *mprev;
	struct esp *esp;
	struct esptail *esptail;
	const struct esp_algorithm *algo;
	u_int32_t spi;
	u_int8_t nxt = 0;
	size_t plen;	/*payload length to be encrypted*/
	size_t espoff;
	int ivlen;
	int afnumber;
	size_t extendsiz;
	int error = 0;
	struct ipsecstat *stat;
	struct udphdr *udp = NULL;
	int	udp_encapsulate = (sav->flags & SADB_X_EXT_NATT && af == AF_INET &&
			(esp_udp_encap_port & 0xFFFF) != 0);

	KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_START, sav->ivlen,0,0,0,0);
	switch (af) {
#if INET
	case AF_INET:
		afnumber = 4;
		stat = &ipsecstat;
		break;
#endif
#if INET6
	case AF_INET6:
		afnumber = 6;
		stat = &ipsec6stat;
		break;
#endif
	default:
		ipseclog((LOG_ERR, "esp_output: unsupported af %d\n", af));
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 1,0,0,0,0);
		return 0;	/* no change at all */
	}

	/* some sanity check */
	if ((sav->flags & SADB_X_EXT_OLD) == 0 && !sav->replay) {
		switch (af) {
#if INET
		case AF_INET:
		    {
			struct ip *ip;

			ip = mtod(m, struct ip *);
			ipseclog((LOG_DEBUG, "esp4_output: internal error: "
				"sav->replay is null: %x->%x, SPI=%u\n",
				(u_int32_t)ntohl(ip->ip_src.s_addr),
				(u_int32_t)ntohl(ip->ip_dst.s_addr),
				(u_int32_t)ntohl(sav->spi)));
			IPSEC_STAT_INCREMENT(ipsecstat.out_inval);
			break;
		    }
#endif /*INET*/
#if INET6
		case AF_INET6:
			ipseclog((LOG_DEBUG, "esp6_output: internal error: "
				"sav->replay is null: SPI=%u\n",
				(u_int32_t)ntohl(sav->spi)));
			IPSEC_STAT_INCREMENT(ipsec6stat.out_inval);
			break;
#endif /*INET6*/
		default:
			panic("esp_output: should not reach here");
		}
		m_freem(m);
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 2,0,0,0,0);
		return EINVAL;
	}

	algo = esp_algorithm_lookup(sav->alg_enc);
	if (!algo) {
		ipseclog((LOG_ERR, "esp_output: unsupported algorithm: "
		    "SPI=%u\n", (u_int32_t)ntohl(sav->spi)));
		m_freem(m);
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 3,0,0,0,0);
		return EINVAL;
	}
	spi = sav->spi;
	ivlen = sav->ivlen;
	/* should be okey */
	if (ivlen < 0) {
		panic("invalid ivlen");
	}

    {
	/*
	 * insert ESP header.
	 * XXX inserts ESP header right after IPv4 header.  should
	 * chase the header chain.
	 * XXX sequential number
	 */
#if INET
	struct ip *ip = NULL;
#endif
#if INET6
	struct ip6_hdr *ip6 = NULL;
#endif
	size_t esplen;	/* sizeof(struct esp/newesp) */
	size_t esphlen;	/* sizeof(struct esp/newesp) + ivlen */
	size_t hlen = 0;	/* ip header len */

	if (sav->flags & SADB_X_EXT_OLD) {
		/* RFC 1827 */
		esplen = sizeof(struct esp);
	} else {
		/* RFC 2406 */
		if (sav->flags & SADB_X_EXT_DERIV)
			esplen = sizeof(struct esp);
		else
			esplen = sizeof(struct newesp);
	}
	esphlen = esplen + ivlen;

	for (mprev = m; mprev && mprev->m_next != md; mprev = mprev->m_next)
		;
	if (mprev == NULL || mprev->m_next != md) {
		ipseclog((LOG_DEBUG, "esp%d_output: md is not in chain\n",
		    afnumber));
		m_freem(m);
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 4,0,0,0,0);
		return EINVAL;
	}

	plen = 0;
	for (n = md; n; n = n->m_next)
		plen += n->m_len;

	switch (af) {
#if INET
	case AF_INET:
		ip = mtod(m, struct ip *);
#ifdef _IP_VHL
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;
#else
		hlen = ip->ip_hl << 2;
#endif
		break;
#endif
#if INET6
	case AF_INET6:
		ip6 = mtod(m, struct ip6_hdr *);
		hlen = sizeof(*ip6);
		break;
#endif
	}

	/* make the packet over-writable */
	mprev->m_next = NULL;
	if ((md = ipsec_copypkt(md)) == NULL) {
		m_freem(m);
		error = ENOBUFS;
		goto fail;
	}
	mprev->m_next = md;
	
	/* 
	 * Translate UDP source port back to its original value.
	 * SADB_X_EXT_NATT_MULTIPLEUSERS is only set for transort mode.
	 */
	if ((sav->flags & SADB_X_EXT_NATT_MULTIPLEUSERS) != 0) {
		/* if not UDP - drop it */
		if (ip->ip_p != IPPROTO_UDP)	{
			IPSEC_STAT_INCREMENT(ipsecstat.out_inval);
			m_freem(m);
			error = EINVAL;
			goto fail;
		}			
		
		udp = mtod(md, struct udphdr *);

		/* if src port not set in sav - find it */
		if (sav->natt_encapsulated_src_port == 0)
			if (key_natt_get_translated_port(sav) == 0) {
				m_freem(m);
				error = EINVAL;
				goto fail;
			}
		if (sav->remote_ike_port == htons(udp->uh_dport)) {
			/* translate UDP port */
			udp->uh_dport = sav->natt_encapsulated_src_port;
			udp->uh_sum = 0;	/* don't need checksum with ESP auth */
		} else {
			/* drop the packet - can't translate the port */
			IPSEC_STAT_INCREMENT(ipsecstat.out_inval);
			m_freem(m);
			error = EINVAL;
			goto fail;
		}
	}
		

	espoff = m->m_pkthdr.len - plen;
	
	if (udp_encapsulate) {
		esphlen += sizeof(struct udphdr);
		espoff += sizeof(struct udphdr);
	}

	/*
	 * grow the mbuf to accomodate ESP header.
	 * before: IP ... payload
	 * after:  IP ... [UDP] ESP IV payload
	 */
	if (M_LEADINGSPACE(md) < esphlen || (md->m_flags & M_EXT) != 0) {
		MGET(n, M_DONTWAIT, MT_DATA);
		if (!n) {
			m_freem(m);
			error = ENOBUFS;
			goto fail;
		}
		n->m_len = esphlen;
		mprev->m_next = n;
		n->m_next = md;
		m->m_pkthdr.len += esphlen;
		if (udp_encapsulate) {
			udp = mtod(n, struct udphdr *);
			esp = (struct esp *)(void *)((caddr_t)udp + sizeof(struct udphdr));
		} else {
			esp = mtod(n, struct esp *);
		}
	} else {
		md->m_len += esphlen;
		md->m_data -= esphlen;
		m->m_pkthdr.len += esphlen;
		esp = mtod(md, struct esp *);
		if (udp_encapsulate) {
			udp = mtod(md, struct udphdr *);
			esp = (struct esp *)(void *)((caddr_t)udp + sizeof(struct udphdr));
		} else {
			esp = mtod(md, struct esp *);
		}
	}
	
	switch (af) {
#if INET
	case AF_INET:
		if (esphlen < (IP_MAXPACKET - ntohs(ip->ip_len)))
			ip->ip_len = htons(ntohs(ip->ip_len) + esphlen);
		else {
			ipseclog((LOG_ERR,
			    "IPv4 ESP output: size exceeds limit\n"));
			IPSEC_STAT_INCREMENT(ipsecstat.out_inval);
			m_freem(m);
			error = EMSGSIZE;
			goto fail;
		}
		break;
#endif
#if INET6
	case AF_INET6:
		/* total packet length will be computed in ip6_output() */
		break;
#endif
	}
    }

	/* initialize esp header. */
	esp->esp_spi = spi;
	if ((sav->flags & SADB_X_EXT_OLD) == 0) {
		struct newesp *nesp;
		nesp = (struct newesp *)esp;
		if (sav->replay->count == ~0) {
			if ((sav->flags & SADB_X_EXT_CYCSEQ) == 0) {
				/* XXX Is it noisy ? */
				ipseclog((LOG_WARNING,
				    "replay counter overflowed. %s\n",
				    ipsec_logsastr(sav)));
				IPSEC_STAT_INCREMENT(stat->out_inval);
				m_freem(m);
				KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 5,0,0,0,0);
				return EINVAL;
			}
		}
		lck_mtx_lock(sadb_mutex);
		sav->replay->count++;
		lck_mtx_unlock(sadb_mutex);
		/*
		 * XXX sequence number must not be cycled, if the SA is
		 * installed by IKE daemon.
		 */
		nesp->esp_seq = htonl(sav->replay->count);
	}

    {
	/*
	 * find the last mbuf. make some room for ESP trailer.
	 */
#if INET
	struct ip *ip = NULL;
#endif
	size_t padbound;
	u_char *extend;
	int i;
	int randpadmax;

	if (algo->padbound)
		padbound = algo->padbound;
	else
		padbound = 4;
	/* ESP packet, including nxthdr field, must be length of 4n */
	if (padbound < 4)
		padbound = 4;
	
	extendsiz = padbound - (plen % padbound);
	if (extendsiz == 1)
		extendsiz = padbound + 1;

	/* random padding */
	switch (af) {
#if INET
	case AF_INET:
		randpadmax = ip4_esp_randpad;
		break;
#endif
#if INET6
	case AF_INET6:
		randpadmax = ip6_esp_randpad;
		break;
#endif
	default:
		randpadmax = -1;
		break;
	}
	if (randpadmax < 0 || plen + extendsiz >= randpadmax)
		;
	else {
		int pad;

		/* round */
		randpadmax = (randpadmax / padbound) * padbound;
		pad = (randpadmax - plen + extendsiz) / padbound;

		if (pad > 0)
			pad = (random() % pad) * padbound;
		else
			pad = 0;

		/*
		 * make sure we do not pad too much.
		 * MLEN limitation comes from the trailer attachment
		 * code below.
		 * 256 limitation comes from sequential padding.
		 * also, the 1-octet length field in ESP trailer imposes
		 * limitation (but is less strict than sequential padding
		 * as length field do not count the last 2 octets).
		 */
		if (extendsiz + pad <= MLEN && extendsiz + pad < 256)
			extendsiz += pad;
	}

#if DIAGNOSTIC
	if (extendsiz > MLEN || extendsiz >= 256)
		panic("extendsiz too big in esp_output");
#endif

	n = m;
	while (n->m_next)
		n = n->m_next;

	/*
	 * if M_EXT, the external mbuf data may be shared among
	 * two consequtive TCP packets, and it may be unsafe to use the
	 * trailing space.
	 */
	if (!(n->m_flags & M_EXT) && extendsiz < M_TRAILINGSPACE(n)) {
		extend = mtod(n, u_char *) + n->m_len;
		n->m_len += extendsiz;
		m->m_pkthdr.len += extendsiz;
	} else {
		struct mbuf *nn;

		MGET(nn, M_DONTWAIT, MT_DATA);
		if (!nn) {
			ipseclog((LOG_DEBUG, "esp%d_output: can't alloc mbuf",
			    afnumber));
			m_freem(m);
			error = ENOBUFS;
			goto fail;
		}
		extend = mtod(nn, u_char *);
		nn->m_len = extendsiz;
		nn->m_next = NULL;
		n->m_next = nn;
		n = nn;
		m->m_pkthdr.len += extendsiz;
	}
	switch (sav->flags & SADB_X_EXT_PMASK) {
	case SADB_X_EXT_PRAND:
		key_randomfill(extend, extendsiz);
		break;
	case SADB_X_EXT_PZERO:
		bzero(extend, extendsiz);
		break;
	case SADB_X_EXT_PSEQ:
		for (i = 0; i < extendsiz; i++)
			extend[i] = (i + 1) & 0xff;
		break;
	}
	
	nxt = *nexthdrp;
	if (udp_encapsulate) {
		*nexthdrp = IPPROTO_UDP;

		/* Fill out the UDP header */
		udp->uh_sport = ntohs((u_short)esp_udp_encap_port);
		udp->uh_dport = ntohs(sav->remote_ike_port);
//		udp->uh_len set later, after all length tweaks are complete
		udp->uh_sum = 0;
		
		/* Update last sent so we know if we need to send keepalive */
		sav->natt_last_activity = natt_now;
	} else {
		*nexthdrp = IPPROTO_ESP;
	}

	/* initialize esp trailer. */
	esptail = (struct esptail *)
		(mtod(n, u_int8_t *) + n->m_len - sizeof(struct esptail));
	esptail->esp_nxt = nxt;
	esptail->esp_padlen = extendsiz - 2;

	/* modify IP header (for ESP header part only) */
	switch (af) {
#if INET
	case AF_INET:
		ip = mtod(m, struct ip *);
		if (extendsiz < (IP_MAXPACKET - ntohs(ip->ip_len)))
			ip->ip_len = htons(ntohs(ip->ip_len) + extendsiz);
		else {
			ipseclog((LOG_ERR,
			    "IPv4 ESP output: size exceeds limit\n"));
			IPSEC_STAT_INCREMENT(ipsecstat.out_inval);
			m_freem(m);
			error = EMSGSIZE;
			goto fail;
		}
		break;
#endif
#if INET6
	case AF_INET6:
		/* total packet length will be computed in ip6_output() */
		break;
#endif
	}
    }

	/*
	 * pre-compute and cache intermediate key
	 */
	error = esp_schedule(algo, sav);
	if (error) {
		m_freem(m);
		IPSEC_STAT_INCREMENT(stat->out_inval);
		goto fail;
	}

	/*
	 * encrypt the packet, based on security association
	 * and the algorithm specified.
	 */
	if (!algo->encrypt)
		panic("internal error: no encrypt function");
	KERNEL_DEBUG(DBG_FNC_ENCRYPT | DBG_FUNC_START, 0,0,0,0,0);
	if ((*algo->encrypt)(m, espoff, plen + extendsiz, sav, algo, ivlen)) {
		/* m is already freed */
		ipseclog((LOG_ERR, "packet encryption failure\n"));
		IPSEC_STAT_INCREMENT(stat->out_inval);
		error = EINVAL;
		KERNEL_DEBUG(DBG_FNC_ENCRYPT | DBG_FUNC_END, 1,error,0,0,0);
		goto fail;
	}
	KERNEL_DEBUG(DBG_FNC_ENCRYPT | DBG_FUNC_END, 2,0,0,0,0);

	/*
	 * calculate ICV if required.
	 */
	if (!sav->replay)
		goto noantireplay;
	if (!sav->key_auth)
		goto noantireplay;
	if (sav->key_auth == SADB_AALG_NONE)
		goto noantireplay;

    {
		const struct ah_algorithm *aalgo;
		u_char authbuf[AH_MAXSUMSIZE] __attribute__((aligned(4)));
		u_char *p;
		size_t siz;
	#if INET
		struct ip *ip;
	#endif
	
		aalgo = ah_algorithm_lookup(sav->alg_auth);
		if (!aalgo)
			goto noantireplay;
		siz = ((aalgo->sumsiz)(sav) + 3) & ~(4 - 1);
		if (AH_MAXSUMSIZE < siz)
			panic("assertion failed for AH_MAXSUMSIZE");
	
		if (esp_auth(m, espoff, m->m_pkthdr.len - espoff, sav, authbuf)) {
			ipseclog((LOG_ERR, "ESP checksum generation failure\n"));
			m_freem(m);
			error = EINVAL;
			IPSEC_STAT_INCREMENT(stat->out_inval);
			goto fail;
		}
	
		n = m;
		while (n->m_next)
			n = n->m_next;
	
		if (!(n->m_flags & M_EXT) && siz < M_TRAILINGSPACE(n)) { /* XXX */
			n->m_len += siz;
			m->m_pkthdr.len += siz;
			p = mtod(n, u_char *) + n->m_len - siz;
		} else {
			struct mbuf *nn;
	
			MGET(nn, M_DONTWAIT, MT_DATA);
			if (!nn) {
				ipseclog((LOG_DEBUG, "can't alloc mbuf in esp%d_output",
					afnumber));
				m_freem(m);
				error = ENOBUFS;
				goto fail;
			}
			nn->m_len = siz;
			nn->m_next = NULL;
			n->m_next = nn;
			n = nn;
			m->m_pkthdr.len += siz;
			p = mtod(nn, u_char *);
		}
		bcopy(authbuf, p, siz);
	
		/* modify IP header (for ESP header part only) */
		switch (af) {
	#if INET
		case AF_INET:
			ip = mtod(m, struct ip *);
			if (siz < (IP_MAXPACKET - ntohs(ip->ip_len)))
				ip->ip_len = htons(ntohs(ip->ip_len) + siz);
			else {
				ipseclog((LOG_ERR,
					"IPv4 ESP output: size exceeds limit\n"));
				IPSEC_STAT_INCREMENT(ipsecstat.out_inval);
				m_freem(m);
				error = EMSGSIZE;
				goto fail;
			}
			break;
	#endif
	#if INET6
		case AF_INET6:
			/* total packet length will be computed in ip6_output() */
			break;
	#endif
		}
    }
    
	if (udp_encapsulate) {
		struct ip *ip;
		ip = mtod(m, struct ip *);
		udp->uh_ulen = htons(ntohs(ip->ip_len) - (IP_VHL_HL(ip->ip_vhl) << 2));
	}


noantireplay:
	lck_mtx_lock(sadb_mutex);
	if (!m) {
		ipseclog((LOG_ERR,
		    "NULL mbuf after encryption in esp%d_output", afnumber));
	} else
		stat->out_success++;
	stat->out_esphist[sav->alg_enc]++;
	lck_mtx_unlock(sadb_mutex);
	key_sa_recordxfer(sav, m);
	KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 6,0,0,0,0);
	return 0;

fail:
#if 1
	KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 7,error,0,0,0);
	return error;
#else
	panic("something bad in esp_output");
#endif
}

#if INET
int
esp4_output(m, sav)
	struct mbuf *m;
	struct secasvar *sav;
{
	struct ip *ip;
	if (m->m_len < sizeof(struct ip)) {
		ipseclog((LOG_DEBUG, "esp4_output: first mbuf too short\n"));
		m_freem(m);
		return EINVAL;
	}
	ip = mtod(m, struct ip *);
	/* XXX assumes that m->m_next points to payload */
	return esp_output(m, &ip->ip_p, m->m_next, AF_INET, sav);
}
#endif /*INET*/

#if INET6
int
esp6_output(m, nexthdrp, md, sav)
	struct mbuf *m;
	u_char *nexthdrp;
	struct mbuf *md;
	struct secasvar *sav;
{
	if (m->m_len < sizeof(struct ip6_hdr)) {
		ipseclog((LOG_DEBUG, "esp6_output: first mbuf too short\n"));
		m_freem(m);
		return EINVAL;
	}
	return esp_output(m, nexthdrp, md, AF_INET6, sav);
}
#endif /*INET6*/
