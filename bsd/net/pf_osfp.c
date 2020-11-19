/*
 * Copyright (c) 2007-2020 Apple Inc. All rights reserved.
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

/*	$apfw: pf_osfp.c,v 1.4 2008/08/27 00:01:32 jhw Exp $ */
/*	$OpenBSD: pf_osfp.c,v 1.12 2006/12/13 18:14:10 itojun Exp $ */

/*
 * Copyright (c) 2003 Mike Frantzen <frantzen@w4g.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include <machine/endian.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/mbuf.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>

#include <net/if.h>
#include <net/pfvar.h>

#include <netinet/ip6.h>
#include <netinet6/in6_var.h>

#define DPFPRINTF(format, x...)                 \
	if (pf_status.debug >= PF_DEBUG_NOISY)  \
	        printf(format, ##x)

static SLIST_HEAD(pf_osfp_list, pf_os_fingerprint) pf_osfp_list;
static struct pool pf_osfp_entry_pl;
static struct pool pf_osfp_pl;

static struct pf_os_fingerprint *pf_osfp_find(struct pf_osfp_list *,
    struct pf_os_fingerprint *, u_int8_t);
static struct pf_os_fingerprint *pf_osfp_find_exact(struct pf_osfp_list *,
    struct pf_os_fingerprint *);
static void pf_osfp_insert(struct pf_osfp_list *, struct pf_os_fingerprint *);


/*
 * Passively fingerprint the OS of the host (IPv4 TCP SYN packets only)
 * Returns the list of possible OSes.
 */
struct pf_osfp_enlist *
pf_osfp_fingerprint(struct pf_pdesc *pd, pbuf_t *pbuf, int off,
    const struct tcphdr *tcp)
{
	struct ip *ip;
	struct ip6_hdr *ip6;
	char hdr[60];

	if ((pd->af != PF_INET && pd->af != PF_INET6) ||
	    pd->proto != IPPROTO_TCP ||
	    (tcp->th_off << 2) < (int)sizeof(*tcp)) {
		return NULL;
	}

	if (pd->af == PF_INET) {
		ip = pbuf->pb_data;
		ip6 = (struct ip6_hdr *)NULL;
	} else {
		ip = (struct ip *)NULL;
		ip6 = pbuf->pb_data;
	}
	if (!pf_pull_hdr(pbuf, off, hdr, tcp->th_off << 2, NULL, NULL,
	        pd->af)) {
		return NULL;
	}

	return pf_osfp_fingerprint_hdr(ip, ip6, (struct tcphdr *)(void *)hdr);
}

struct pf_osfp_enlist *
pf_osfp_fingerprint_hdr(const struct ip *ip, const struct ip6_hdr *ip6,
    const struct tcphdr *tcp)
{
	struct pf_os_fingerprint fp, *fpresult;
	int cnt, optlen = 0;
	const u_int8_t *optp;
	char srcname[128];

	if ((tcp->th_flags & (TH_SYN | TH_ACK)) != TH_SYN) {
		return NULL;
	}
	if (ip) {
		if ((ip->ip_off & htons(IP_OFFMASK)) != 0) {
			return NULL;
		}
	}

	memset(&fp, 0, sizeof(fp));

	if (ip) {
		fp.fp_psize = ntohs(ip->ip_len);
		fp.fp_ttl = ip->ip_ttl;
		if (ip->ip_off & htons(IP_DF)) {
			fp.fp_flags |= PF_OSFP_DF;
		}
		(void) inet_ntop(AF_INET, &ip->ip_src, srcname,
		    (socklen_t)sizeof(srcname));
	} else if (ip6) {
		/* jumbo payload? */
		fp.fp_psize = sizeof(struct ip6_hdr) + ntohs(ip6->ip6_plen);
		fp.fp_ttl = ip6->ip6_hlim;
		fp.fp_flags |= PF_OSFP_DF;
		fp.fp_flags |= PF_OSFP_INET6;
		(void) inet_ntop(AF_INET6, &ip6->ip6_src, srcname,
		    (socklen_t)sizeof(srcname));
	} else {
		return NULL;
	}
	fp.fp_wsize = ntohs(tcp->th_win);


	cnt = (tcp->th_off << 2) - sizeof(*tcp);
	optp = (const u_int8_t *)((const char *)tcp + sizeof(*tcp));
	for (; cnt > 0; cnt -= optlen, optp += optlen) {
		if (*optp == TCPOPT_EOL) {
			break;
		}

		fp.fp_optcnt++;
		if (*optp == TCPOPT_NOP) {
			fp.fp_tcpopts = (fp.fp_tcpopts << PF_OSFP_TCPOPT_BITS) |
			    PF_OSFP_TCPOPT_NOP;
			optlen = 1;
		} else {
			if (cnt < 2) {
				return NULL;
			}
			optlen = optp[1];
			if (optlen > cnt || optlen < 2) {
				return NULL;
			}
			switch (*optp) {
			case TCPOPT_MAXSEG:
				if (optlen >= TCPOLEN_MAXSEG) {
					memcpy(&fp.fp_mss, &optp[2],
					    sizeof(fp.fp_mss));
				}
				fp.fp_tcpopts = (fp.fp_tcpopts <<
				        PF_OSFP_TCPOPT_BITS) | PF_OSFP_TCPOPT_MSS;
#if BYTE_ORDER != BIG_ENDIAN
				NTOHS(fp.fp_mss);
#endif
				break;
			case TCPOPT_WINDOW:
				if (optlen >= TCPOLEN_WINDOW) {
					memcpy(&fp.fp_wscale, &optp[2],
					    sizeof(fp.fp_wscale));
				}
				fp.fp_tcpopts = (fp.fp_tcpopts <<
				        PF_OSFP_TCPOPT_BITS) |
				    PF_OSFP_TCPOPT_WSCALE;
				break;
			case TCPOPT_SACK_PERMITTED:
				fp.fp_tcpopts = (fp.fp_tcpopts <<
				        PF_OSFP_TCPOPT_BITS) | PF_OSFP_TCPOPT_SACK;
				break;
			case TCPOPT_TIMESTAMP:
				if (optlen >= TCPOLEN_TIMESTAMP) {
					u_int32_t ts;
					memcpy(&ts, &optp[2], sizeof(ts));
					if (ts == 0) {
						fp.fp_flags |= PF_OSFP_TS0;
					}
				}
				fp.fp_tcpopts = (fp.fp_tcpopts <<
				        PF_OSFP_TCPOPT_BITS) | PF_OSFP_TCPOPT_TS;
				break;
			default:
				return NULL;
			}
		}
		optlen = MAX(optlen, 1);        /* paranoia */
	}

	DPFPRINTF("fingerprinted %s:%d  %d:%d:%d:%d:%llx (%d) "
	    "(TS=%s,M=%s%d,W=%s%d)\n",
	    srcname, ntohs(tcp->th_sport),
	    fp.fp_wsize, fp.fp_ttl, (fp.fp_flags & PF_OSFP_DF) != 0,
	    fp.fp_psize, (long long int)fp.fp_tcpopts, fp.fp_optcnt,
	    (fp.fp_flags & PF_OSFP_TS0) ? "0" : "",
	    (fp.fp_flags & PF_OSFP_MSS_MOD) ? "%" :
	    (fp.fp_flags & PF_OSFP_MSS_DC) ? "*" : "",
	    fp.fp_mss,
	    (fp.fp_flags & PF_OSFP_WSCALE_MOD) ? "%" :
	    (fp.fp_flags & PF_OSFP_WSCALE_DC) ? "*" : "",
	    fp.fp_wscale);

	if ((fpresult = pf_osfp_find(&pf_osfp_list, &fp,
	    PF_OSFP_MAXTTL_OFFSET))) {
		return &fpresult->fp_oses;
	}
	return NULL;
}

/* Match a fingerprint ID against a list of OSes */
int
pf_osfp_match(struct pf_osfp_enlist *list, pf_osfp_t os)
{
	struct pf_osfp_entry *entry;
	int os_class, os_version, os_subtype;
	int en_class, en_version, en_subtype;

	if (os == PF_OSFP_ANY) {
		return 1;
	}
	if (list == NULL) {
		DPFPRINTF("osfp no match against %x\n", os);
		return os == PF_OSFP_UNKNOWN;
	}
	PF_OSFP_UNPACK(os, os_class, os_version, os_subtype);
	SLIST_FOREACH(entry, list, fp_entry) {
		PF_OSFP_UNPACK(entry->fp_os, en_class, en_version, en_subtype);
		if ((os_class == PF_OSFP_ANY || en_class == os_class) &&
		    (os_version == PF_OSFP_ANY || en_version == os_version) &&
		    (os_subtype == PF_OSFP_ANY || en_subtype == os_subtype)) {
			DPFPRINTF("osfp matched %s %s %s  %x==%x\n",
			    entry->fp_class_nm, entry->fp_version_nm,
			    entry->fp_subtype_nm, os, entry->fp_os);
			return 1;
		}
	}
	DPFPRINTF("fingerprint 0x%x didn't match\n", os);
	return 0;
}

/* Initialize the OS fingerprint system */
void
pf_osfp_initialize(void)
{
	pool_init(&pf_osfp_entry_pl, sizeof(struct pf_osfp_entry), 0, 0, 0,
	    "pfosfpen", NULL);
	pool_init(&pf_osfp_pl, sizeof(struct pf_os_fingerprint), 0, 0, 0,
	    "pfosfp", NULL);
	SLIST_INIT(&pf_osfp_list);
}

#if 0
void
pf_osfp_destroy(void)
{
	pf_osfp_flush();

	pool_destroy(&pf_osfp_pl);
	pool_destroy(&pf_osfp_entry_pl);
}
#endif

/* Flush the fingerprint list */
void
pf_osfp_flush(void)
{
	struct pf_os_fingerprint *fp;
	struct pf_osfp_entry *entry;

	while ((fp = SLIST_FIRST(&pf_osfp_list))) {
		SLIST_REMOVE_HEAD(&pf_osfp_list, fp_next);
		while ((entry = SLIST_FIRST(&fp->fp_oses))) {
			SLIST_REMOVE_HEAD(&fp->fp_oses, fp_entry);
			pool_put(&pf_osfp_entry_pl, entry);
		}
		pool_put(&pf_osfp_pl, fp);
	}
}


/* Add a fingerprint */
int
pf_osfp_add(struct pf_osfp_ioctl *fpioc)
{
	struct pf_os_fingerprint *fp, fpadd;
	struct pf_osfp_entry *entry, *uentry;

	memset(&fpadd, 0, sizeof(fpadd));
	fpadd.fp_tcpopts = fpioc->fp_tcpopts;
	fpadd.fp_wsize = fpioc->fp_wsize;
	fpadd.fp_psize = fpioc->fp_psize;
	fpadd.fp_mss = fpioc->fp_mss;
	fpadd.fp_flags = fpioc->fp_flags;
	fpadd.fp_optcnt = fpioc->fp_optcnt;
	fpadd.fp_wscale = fpioc->fp_wscale;
	fpadd.fp_ttl = fpioc->fp_ttl;

	uentry = &fpioc->fp_os;
	uentry->fp_entry.sle_next = NULL;
	uentry->fp_class_nm[sizeof(uentry->fp_class_nm) - 1] = '\0';
	uentry->fp_version_nm[sizeof(uentry->fp_version_nm) - 1] = '\0';
	uentry->fp_subtype_nm[sizeof(uentry->fp_subtype_nm) - 1] = '\0';

	DPFPRINTF("adding osfp %s %s %s = %s%d:%d:%d:%s%d:0x%llx %d "
	    "(TS=%s,M=%s%d,W=%s%d) %x\n",
	    fpioc->fp_os.fp_class_nm, fpioc->fp_os.fp_version_nm,
	    fpioc->fp_os.fp_subtype_nm,
	    (fpadd.fp_flags & PF_OSFP_WSIZE_MOD) ? "%" :
	    (fpadd.fp_flags & PF_OSFP_WSIZE_MSS) ? "S" :
	    (fpadd.fp_flags & PF_OSFP_WSIZE_MTU) ? "T" :
	    (fpadd.fp_flags & PF_OSFP_WSIZE_DC) ? "*" : "",
	    fpadd.fp_wsize,
	    fpadd.fp_ttl,
	    (fpadd.fp_flags & PF_OSFP_DF) ? 1 : 0,
	    (fpadd.fp_flags & PF_OSFP_PSIZE_MOD) ? "%" :
	    (fpadd.fp_flags & PF_OSFP_PSIZE_DC) ? "*" : "",
	    fpadd.fp_psize,
	    (long long int)fpadd.fp_tcpopts, fpadd.fp_optcnt,
	    (fpadd.fp_flags & PF_OSFP_TS0) ? "0" : "",
	    (fpadd.fp_flags & PF_OSFP_MSS_MOD) ? "%" :
	    (fpadd.fp_flags & PF_OSFP_MSS_DC) ? "*" : "",
	    fpadd.fp_mss,
	    (fpadd.fp_flags & PF_OSFP_WSCALE_MOD) ? "%" :
	    (fpadd.fp_flags & PF_OSFP_WSCALE_DC) ? "*" : "",
	    fpadd.fp_wscale,
	    fpioc->fp_os.fp_os);


	if ((fp = pf_osfp_find_exact(&pf_osfp_list, &fpadd))) {
		SLIST_FOREACH(entry, &fp->fp_oses, fp_entry) {
			if (PF_OSFP_ENTRY_EQ(entry, &fpioc->fp_os)) {
				return EEXIST;
			}
		}
		if ((entry = pool_get(&pf_osfp_entry_pl, PR_WAITOK)) == NULL) {
			return ENOMEM;
		}
	} else {
		if ((fp = pool_get(&pf_osfp_pl, PR_WAITOK)) == NULL) {
			return ENOMEM;
		}
		memset(fp, 0, sizeof(*fp));
		fp->fp_tcpopts = fpioc->fp_tcpopts;
		fp->fp_wsize = fpioc->fp_wsize;
		fp->fp_psize = fpioc->fp_psize;
		fp->fp_mss = fpioc->fp_mss;
		fp->fp_flags = fpioc->fp_flags;
		fp->fp_optcnt = fpioc->fp_optcnt;
		fp->fp_wscale = fpioc->fp_wscale;
		fp->fp_ttl = fpioc->fp_ttl;
		SLIST_INIT(&fp->fp_oses);
		if ((entry = pool_get(&pf_osfp_entry_pl, PR_WAITOK)) == NULL) {
			pool_put(&pf_osfp_pl, fp);
			return ENOMEM;
		}
		pf_osfp_insert(&pf_osfp_list, fp);
	}
	memcpy(entry, &fpioc->fp_os, sizeof(*entry));

	/* Make sure the strings are NUL terminated */
	entry->fp_class_nm[sizeof(entry->fp_class_nm) - 1] = '\0';
	entry->fp_version_nm[sizeof(entry->fp_version_nm) - 1] = '\0';
	entry->fp_subtype_nm[sizeof(entry->fp_subtype_nm) - 1] = '\0';

	SLIST_INSERT_HEAD(&fp->fp_oses, entry, fp_entry);

#ifdef PFDEBUG
	if ((fp = pf_osfp_validate())) {
		printf("Invalid fingerprint list\n");
	}
#endif /* PFDEBUG */
	return 0;
}


/* Find a fingerprint in the list */
struct pf_os_fingerprint *
pf_osfp_find(struct pf_osfp_list *list, struct pf_os_fingerprint *find,
    u_int8_t ttldiff)
{
	struct pf_os_fingerprint *f;

#define MATCH_INT(_MOD, _DC, _field)                                    \
	if ((f->fp_flags & _DC) == 0) {                                 \
	        if ((f->fp_flags & _MOD) == 0) {                        \
	                if (f->_field != find->_field)                  \
	                        continue;                               \
	        } else {                                                \
	                if (f->_field == 0 || find->_field % f->_field) \
	                        continue;                               \
	        }                                                       \
	}

	SLIST_FOREACH(f, list, fp_next) {
		if (f->fp_tcpopts != find->fp_tcpopts ||
		    f->fp_optcnt != find->fp_optcnt ||
		    f->fp_ttl < find->fp_ttl ||
		    f->fp_ttl - find->fp_ttl > ttldiff ||
		    (f->fp_flags & (PF_OSFP_DF | PF_OSFP_TS0)) !=
		    (find->fp_flags & (PF_OSFP_DF | PF_OSFP_TS0))) {
			continue;
		}

		MATCH_INT(PF_OSFP_PSIZE_MOD, PF_OSFP_PSIZE_DC, fp_psize)
		MATCH_INT(PF_OSFP_MSS_MOD, PF_OSFP_MSS_DC, fp_mss)
		MATCH_INT(PF_OSFP_WSCALE_MOD, PF_OSFP_WSCALE_DC, fp_wscale)
		if ((f->fp_flags & PF_OSFP_WSIZE_DC) == 0) {
			if (f->fp_flags & PF_OSFP_WSIZE_MSS) {
				if (find->fp_mss == 0) {
					continue;
				}

/*
 * Some "smart" NAT devices and DSL routers will tweak the MSS size and
 * will set it to whatever is suitable for the link type.
 */
#define SMART_MSS       1460
				if ((find->fp_wsize % find->fp_mss ||
				    find->fp_wsize / find->fp_mss !=
				    f->fp_wsize) &&
				    (find->fp_wsize % SMART_MSS ||
				    find->fp_wsize / SMART_MSS !=
				    f->fp_wsize)) {
					continue;
				}
			} else if (f->fp_flags & PF_OSFP_WSIZE_MTU) {
				if (find->fp_mss == 0) {
					continue;
				}

#define MTUOFF  (sizeof (struct ip) + sizeof (struct tcphdr))
#define SMART_MTU       (SMART_MSS + MTUOFF)
				if ((find->fp_wsize % (find->fp_mss + MTUOFF) ||
				    find->fp_wsize / (find->fp_mss + MTUOFF) !=
				    f->fp_wsize) &&
				    (find->fp_wsize % SMART_MTU ||
				    find->fp_wsize / SMART_MTU !=
				    f->fp_wsize)) {
					continue;
				}
			} else if (f->fp_flags & PF_OSFP_WSIZE_MOD) {
				if (f->fp_wsize == 0 || find->fp_wsize %
				    f->fp_wsize) {
					continue;
				}
			} else {
				if (f->fp_wsize != find->fp_wsize) {
					continue;
				}
			}
		}
		return f;
	}

	return NULL;
}

/* Find an exact fingerprint in the list */
struct pf_os_fingerprint *
pf_osfp_find_exact(struct pf_osfp_list *list, struct pf_os_fingerprint *find)
{
	struct pf_os_fingerprint *f;

	SLIST_FOREACH(f, list, fp_next) {
		if (f->fp_tcpopts == find->fp_tcpopts &&
		    f->fp_wsize == find->fp_wsize &&
		    f->fp_psize == find->fp_psize &&
		    f->fp_mss == find->fp_mss &&
		    f->fp_flags == find->fp_flags &&
		    f->fp_optcnt == find->fp_optcnt &&
		    f->fp_wscale == find->fp_wscale &&
		    f->fp_ttl == find->fp_ttl) {
			return f;
		}
	}

	return NULL;
}

/* Insert a fingerprint into the list */
void
pf_osfp_insert(struct pf_osfp_list *list, struct pf_os_fingerprint *ins)
{
	struct pf_os_fingerprint *f, *prev = NULL;

	/* XXX need to go semi tree based.  can key on tcp options */

	SLIST_FOREACH(f, list, fp_next)
	prev = f;
	if (prev) {
		SLIST_INSERT_AFTER(prev, ins, fp_next);
	} else {
		SLIST_INSERT_HEAD(list, ins, fp_next);
	}
}

/* Fill a fingerprint by its number (from an ioctl) */
int
pf_osfp_get(struct pf_osfp_ioctl *fpioc)
{
	struct pf_os_fingerprint *fp;
	struct pf_osfp_entry *entry;
	int num = fpioc->fp_getnum;
	int i = 0;


	memset(fpioc, 0, sizeof(*fpioc));
	SLIST_FOREACH(fp, &pf_osfp_list, fp_next) {
		SLIST_FOREACH(entry, &fp->fp_oses, fp_entry) {
			if (i++ == num) {
				fpioc->fp_mss = fp->fp_mss;
				fpioc->fp_wsize = fp->fp_wsize;
				fpioc->fp_flags = fp->fp_flags;
				fpioc->fp_psize = fp->fp_psize;
				fpioc->fp_ttl = fp->fp_ttl;
				fpioc->fp_wscale = fp->fp_wscale;
				fpioc->fp_getnum = num;
				memcpy(&fpioc->fp_os, entry,
				    sizeof(fpioc->fp_os));
				fpioc->fp_os.fp_entry.sle_next = NULL;
				return 0;
			}
		}
	}

	return EBUSY;
}


/* Validate that each signature is reachable */
struct pf_os_fingerprint *
pf_osfp_validate(void)
{
	struct pf_os_fingerprint *f, *f2, find;

	SLIST_FOREACH(f, &pf_osfp_list, fp_next) {
		memcpy(&find, f, sizeof(find));

		/* We do a few MSS/th_win percolations to make things unique */
		if (find.fp_mss == 0) {
			find.fp_mss = 128;
		}
		if (f->fp_flags & PF_OSFP_WSIZE_MSS) {
			find.fp_wsize *= find.fp_mss;
		} else if (f->fp_flags & PF_OSFP_WSIZE_MTU) {
			find.fp_wsize *= (find.fp_mss + 40);
		} else if (f->fp_flags & PF_OSFP_WSIZE_MOD) {
			find.fp_wsize *= 2;
		}
		if (f != (f2 = pf_osfp_find(&pf_osfp_list, &find, 0))) {
			if (f2) {
				printf("Found \"%s %s %s\" instead of "
				    "\"%s %s %s\"\n",
				    SLIST_FIRST(&f2->fp_oses)->fp_class_nm,
				    SLIST_FIRST(&f2->fp_oses)->fp_version_nm,
				    SLIST_FIRST(&f2->fp_oses)->fp_subtype_nm,
				    SLIST_FIRST(&f->fp_oses)->fp_class_nm,
				    SLIST_FIRST(&f->fp_oses)->fp_version_nm,
				    SLIST_FIRST(&f->fp_oses)->fp_subtype_nm);
			} else {
				printf("Couldn't find \"%s %s %s\"\n",
				    SLIST_FIRST(&f->fp_oses)->fp_class_nm,
				    SLIST_FIRST(&f->fp_oses)->fp_version_nm,
				    SLIST_FIRST(&f->fp_oses)->fp_subtype_nm);
			}
			return f;
		}
	}
	return NULL;
}
