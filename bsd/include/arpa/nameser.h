/*
 * Copyright (c) 1983, 1989, 1993
 *    The Regents of the University of California.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by the University of
 * 	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 *	From: Id: nameser.h,v 8.16 1998/02/06 00:35:58 halley Exp
 * $FreeBSD: src/include/arpa/nameser.h,v 1.12.2.1 1999/08/29 14:39:00 peter Exp $
 */

#ifndef _ARPA_NAMESER_H_
#define _ARPA_NAMESER_H_

#define BIND_4_COMPAT

#include <sys/types.h>
#include <sys/cdefs.h>

/*
 * revision information.  this is the release date in YYYYMMDD format.
 * it can change every day so the right thing to do with it is use it
 * in preprocessor commands such as "#if (__NAMESER > 19931104)".  do not
 * compare for equality; rather, use it to determine whether your libnameser.a
 * is new enough to contain a certain feature.
 */

/* XXXRTH I made this bigger than __BIND in 4.9.5 T6B */
#define __NAMESER	19961001	/* New interface version stamp. */

/*
 * Define constants based on RFC 883, RFC 1034, RFC 1035
 */
#define NS_PACKETSZ	512	/* maximum packet size */
#define NS_MAXDNAME	1025	/* maximum domain name */
#define NS_MAXCDNAME	255	/* maximum compressed domain name */
#define NS_MAXLABEL	63	/* maximum length of domain label */
#define NS_HFIXEDSZ	12	/* #/bytes of fixed data in header */
#define NS_QFIXEDSZ	4	/* #/bytes of fixed data in query */
#define NS_RRFIXEDSZ	10	/* #/bytes of fixed data in r record */
#define NS_INT32SZ	4	/* #/bytes of data in a u_int32_t */
#define NS_INT16SZ	2	/* #/bytes of data in a u_int16_t */
#define NS_INT8SZ	1	/* #/bytes of data in a u_int8_t */
#define NS_INADDRSZ	4	/* IPv4 T_A */
#define NS_IN6ADDRSZ	16	/* IPv6 T_AAAA */
#define NS_CMPRSFLGS	0xc0	/* Flag bits indicating name compression. */
#define NS_DEFAULTPORT	53	/* For both TCP and UDP. */

/*
 * These can be expanded with synonyms, just keep ns_parse.c:ns_parserecord()
 * in synch with it.
 */
typedef enum __ns_sect {
	ns_s_qd = 0,		/* Query: Question. */
	ns_s_zn = 0,		/* Update: Zone. */
	ns_s_an = 1,		/* Query: Answer. */
	ns_s_pr = 1,		/* Update: Prerequisites. */
	ns_s_ns = 2,		/* Query: Name servers. */
	ns_s_ud = 2,		/* Update: Update. */
	ns_s_ar = 3,		/* Query|Update: Additional records. */
	ns_s_max = 4
} ns_sect;

/*
 * This is a message handle.  It is caller allocated and has no dynamic data.
 * This structure is intended to be opaque to all but ns_parse.c, thus the
 * leading _'s on the member names.  Use the accessor functions, not the _'s.
 */
typedef struct __ns_msg {
	const u_char	*_msg, *_eom;
	u_int16_t	_id, _flags, _counts[ns_s_max];
	const u_char	*_sections[ns_s_max];
	ns_sect		_sect;
	int		_rrnum;
	const u_char	*_ptr;
} ns_msg;

/* Private data structure - do not use from outside library. */
struct _ns_flagdata {  int mask, shift;  };
extern struct _ns_flagdata _ns_flagdata[];

/* Accessor macros - this is part of the public interface. */
#define ns_msg_getflag(handle, flag) ( \
			((handle)._flags & _ns_flagdata[flag].mask) \
			 >> _ns_flagdata[flag].shift \
			)
#define ns_msg_id(handle) ((handle)._id + 0)
#define ns_msg_base(handle) ((handle)._msg + 0)
#define ns_msg_end(handle) ((handle)._eom + 0)
#define ns_msg_size(handle) ((handle)._eom - (handle)._msg)
#define ns_msg_count(handle, section) ((handle)._counts[section] + 0)

/*
 * This is a parsed record.  It is caller allocated and has no dynamic data.
 */
typedef	struct __ns_rr {
	char		name[NS_MAXDNAME];	/* XXX need to malloc */
	u_int16_t	type;
	u_int16_t	class;
	u_int32_t	ttl;
	u_int16_t	rdlength;
	const u_char	*rdata;
} ns_rr;

/* Accessor macros - this is part of the public interface. */
#define ns_rr_name(rr)	(((rr).name[0] != '\0') ? (rr).name : ".")
#define ns_rr_type(rr)	((rr).type + 0)
#define ns_rr_class(rr)	((rr).class + 0)
#define ns_rr_ttl(rr)	((rr).ttl + 0)
#define ns_rr_rdlen(rr)	((rr).rdlength + 0)
#define ns_rr_rdata(rr)	((rr).rdata + 0)

/*
 * These don't have to be in the same order as in the packet flags word,
 * and they can even overlap in some cases, but they will need to be kept
 * in synch with ns_parse.c:ns_flagdata[].
 */
typedef enum __ns_flag {
	ns_f_qr,		/* Question/Response. */
	ns_f_opcode,		/* Operation code. */
	ns_f_aa,		/* Authoritative Answer. */
	ns_f_tc,		/* Truncation occurred. */
	ns_f_rd,		/* Recursion Desired. */
	ns_f_ra,		/* Recursion Available. */
	ns_f_z,			/* MBZ. */
	ns_f_ad,		/* Authentic Data (DNSSEC). */
	ns_f_cd,		/* Checking Disabled (DNSSEC). */
	ns_f_rcode,		/* Response code. */
	ns_f_max
} ns_flag;

/*
 * Currently defined opcodes.
 */
typedef enum __ns_opcode {
	ns_o_query = 0,		/* Standard query. */
	ns_o_iquery = 1,	/* Inverse query (deprecated/unsupported). */
	ns_o_status = 2,	/* Name server status query (unsupported). */
				/* Opcode 3 is undefined/reserved. */
	ns_o_notify = 4,	/* Zone change notification. */
	ns_o_update = 5,	/* Zone update message. */
	ns_o_max = 6
} ns_opcode;

/*
 * Currently defined response codes.
 */
typedef	enum __ns_rcode {
	ns_r_noerror = 0,	/* No error occurred. */
	ns_r_formerr = 1,	/* Format error. */
	ns_r_servfail = 2,	/* Server failure. */
	ns_r_nxdomain = 3,	/* Name error. */
	ns_r_notimpl = 4,	/* Unimplemented. */
	ns_r_refused = 5,	/* Operation refused. */
	/* these are for BIND_UPDATE */
	ns_r_yxdomain = 6,	/* Name exists */
	ns_r_yxrrset = 7,	/* RRset exists */
	ns_r_nxrrset = 8,	/* RRset does not exist */
	ns_r_notauth = 9,	/* Not authoritative for zone */
	ns_r_notzone = 10,	/* Zone of record different from zone section */
	ns_r_max = 11
} ns_rcode;

/* BIND_UPDATE */
typedef enum __ns_update_operation {
	ns_uop_delete = 0,
	ns_uop_add = 1,
	ns_uop_max = 2
} ns_update_operation;

/*
 * This RR-like structure is particular to UPDATE.
 */
struct ns_updrec {
	struct ns_updrec *r_prev;	/* prev record */
	struct ns_updrec *r_next;	/* next record */
	u_int8_t	r_section;	/* ZONE/PREREQUISITE/UPDATE */
	char *		r_dname;	/* owner of the RR */
	u_int16_t	r_class;	/* class number */
	u_int16_t	r_type;		/* type number */
	u_int32_t	r_ttl;		/* time to live */
	u_char *	r_data;		/* rdata fields as text string */
	u_int16_t	r_size;		/* size of r_data field */
	int		r_opcode;	/* type of operation */
	/* following fields for private use by the resolver/server routines */
	struct ns_updrec *r_grpnext;	/* next record when grouped */
	struct databuf *r_dp;		/* databuf to process */
	struct databuf *r_deldp;	/* databuf's deleted/overwritten */
	u_int16_t	r_zone;		/* zone number on server */
};
typedef struct ns_updrec ns_updrec;

/*
 * Currently defined type values for resources and queries.
 */
typedef enum __ns_type {
	ns_t_a = 1,		/* Host address. */
	ns_t_ns = 2,		/* Authoritative server. */
	ns_t_md = 3,		/* Mail destination. */
	ns_t_mf = 4,		/* Mail forwarder. */
	ns_t_cname = 5,		/* Canonical name. */
	ns_t_soa = 6,		/* Start of authority zone. */
	ns_t_mb = 7,		/* Mailbox domain name. */
	ns_t_mg = 8,		/* Mail group member. */
	ns_t_mr = 9,		/* Mail rename name. */
	ns_t_null = 10,		/* Null resource record. */
	ns_t_wks = 11,		/* Well known service. */
	ns_t_ptr = 12,		/* Domain name pointer. */
	ns_t_hinfo = 13,	/* Host information. */
	ns_t_minfo = 14,	/* Mailbox information. */
	ns_t_mx = 15,		/* Mail routing information. */
	ns_t_txt = 16,		/* Text strings. */
	ns_t_rp = 17,		/* Responsible person. */
	ns_t_afsdb = 18,	/* AFS cell database. */
	ns_t_x25 = 19,		/* X_25 calling address. */
	ns_t_isdn = 20,		/* ISDN calling address. */
	ns_t_rt = 21,		/* Router. */
	ns_t_nsap = 22,		/* NSAP address. */
	ns_t_nsap_ptr = 23,	/* Reverse NSAP lookup (deprecated). */
	ns_t_sig = 24,		/* Security signature. */
	ns_t_key = 25,		/* Security key. */
	ns_t_px = 26,		/* X.400 mail mapping. */
	ns_t_gpos = 27,		/* Geographical position (withdrawn). */
	ns_t_aaaa = 28,		/* Ip6 Address. */
	ns_t_loc = 29,		/* Location Information. */
	ns_t_nxt = 30,		/* Next domain (security). */
	ns_t_eid = 31,		/* Endpoint identifier. */
	ns_t_nimloc = 32,	/* Nimrod Locator. */
	ns_t_srv = 33,		/* Server Selection. */
	ns_t_atma = 34,		/* ATM Address */
	ns_t_naptr = 35,	/* Naming Authority PoinTeR */
	/* Query type values which do not appear in resource records. */
	ns_t_ixfr = 251,	/* Incremental zone transfer. */
	ns_t_axfr = 252,	/* Transfer zone of authority. */
	ns_t_mailb = 253,	/* Transfer mailbox records. */
	ns_t_maila = 254,	/* Transfer mail agent records. */
	ns_t_any = 255,		/* Wildcard match. */
	ns_t_max = 65536
} ns_type;

/*
 * Values for class field
 */
typedef enum __ns_class {
	ns_c_in = 1,		/* Internet. */
				/* Class 2 unallocated/unsupported. */
	ns_c_chaos = 3,		/* MIT Chaos-net. */
	ns_c_hs = 4,		/* MIT Hesiod. */
	/* Query class values which do not appear in resource records */
	ns_c_none = 254,	/* for prereq. sections in update requests */
	ns_c_any = 255,		/* Wildcard match. */
	ns_c_max = 65536
} ns_class;

/*
 * Flags field of the KEY RR rdata
 */
#define	NS_KEY_TYPEMASK		0xC000	/* Mask for "type" bits */
#define	NS_KEY_TYPE_AUTH_CONF	0x0000	/* Key usable for both */
#define	NS_KEY_TYPE_CONF_ONLY	0x8000	/* Key usable for confidentiality */
#define	NS_KEY_TYPE_AUTH_ONLY	0x4000	/* Key usable for authentication */
#define	NS_KEY_TYPE_NO_KEY	0xC000	/* No key usable for either; no key */
/* The type bits can also be interpreted independently, as single bits: */
#define	NS_KEY_NO_AUTH		0x8000	/* Key unusable for authentication */
#define	NS_KEY_NO_CONF		0x4000	/* Key unusable for confidentiality */
#define	NS_KEY_EXPERIMENTAL	0x2000	/* Security is *mandatory* if bit=0 */
#define	NS_KEY_RESERVED3	0x1000  /* reserved - must be zero */
#define	NS_KEY_RESERVED4	0x0800  /* reserved - must be zero */
#define	NS_KEY_USERACCOUNT	0x0400	/* key is assoc. with a user acct */
#define	NS_KEY_ENTITY		0x0200	/* key is assoc. with entity eg host */
#define	NS_KEY_ZONEKEY		0x0100	/* key is zone key */
#define	NS_KEY_IPSEC		0x0080  /* key is for IPSEC (host or user)*/
#define	NS_KEY_EMAIL		0x0040  /* key is for email (MIME security) */
#define	NS_KEY_RESERVED10	0x0020  /* reserved - must be zero */
#define	NS_KEY_RESERVED11	0x0010  /* reserved - must be zero */
#define	NS_KEY_SIGNATORYMASK	0x000F	/* key can sign RR's of same name */

#define	NS_KEY_RESERVED_BITMASK ( NS_KEY_RESERVED3 | \
				  NS_KEY_RESERVED4 | \
				  NS_KEY_RESERVED10 | \
				  NS_KEY_RESERVED11 )

/* The Algorithm field of the KEY and SIG RR's is an integer, {1..254} */
#define	NS_ALG_MD5RSA		1	/* MD5 with RSA */
#define	NS_ALG_EXPIRE_ONLY	253	/* No alg, no security */
#define	NS_ALG_PRIVATE_OID	254	/* Key begins with OID giving alg */

/* Signatures */
#define	NS_MD5RSA_MIN_BITS	 512	/* Size of a mod or exp in bits */
#define	NS_MD5RSA_MAX_BITS	2552
	/* Total of binary mod and exp */
#define	NS_MD5RSA_MAX_BYTES	((NS_MD5RSA_MAX_BITS+7/8)*2+3)
	/* Max length of text sig block */
#define	NS_MD5RSA_MAX_BASE64	(((NS_MD5RSA_MAX_BYTES+2)/3)*4)

/* Offsets into SIG record rdata to find various values */
#define	NS_SIG_TYPE	0	/* Type flags */
#define	NS_SIG_ALG	2	/* Algorithm */
#define	NS_SIG_LABELS	3	/* How many labels in name */
#define	NS_SIG_OTTL	4	/* Original TTL */
#define	NS_SIG_EXPIR	8	/* Expiration time */
#define	NS_SIG_SIGNED	12	/* Signature time */
#define	NS_SIG_FOOT	16	/* Key footprint */
#define	NS_SIG_SIGNER	18	/* Domain name of who signed it */

/* How RR types are represented as bit-flags in NXT records */
#define	NS_NXT_BITS 8
#define	NS_NXT_BIT_SET(  n,p) (p[(n)/NS_NXT_BITS] |=  (0x80>>((n)%NS_NXT_BITS)))
#define	NS_NXT_BIT_CLEAR(n,p) (p[(n)/NS_NXT_BITS] &= ~(0x80>>((n)%NS_NXT_BITS)))
#define	NS_NXT_BIT_ISSET(n,p) (p[(n)/NS_NXT_BITS] &   (0x80>>((n)%NS_NXT_BITS)))


/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 */
#define NS_GET16(s, cp) { \
	register u_char *t_cp = (u_char *)(cp); \
	(s) = ((u_int16_t)t_cp[0] << 8) \
	    | ((u_int16_t)t_cp[1]) \
	    ; \
	(cp) += NS_INT16SZ; \
}

#define NS_GET32(l, cp) { \
	register u_char *t_cp = (u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += NS_INT32SZ; \
}

#define NS_PUT16(s, cp) { \
	register u_int16_t t_s = (u_int16_t)(s); \
	register u_char *t_cp = (u_char *)(cp); \
	*t_cp++ = t_s >> 8; \
	*t_cp   = t_s; \
	(cp) += NS_INT16SZ; \
}

#define NS_PUT32(l, cp) { \
	register u_int32_t t_l = (u_int32_t)(l); \
	register u_char *t_cp = (u_char *)(cp); \
	*t_cp++ = t_l >> 24; \
	*t_cp++ = t_l >> 16; \
	*t_cp++ = t_l >> 8; \
	*t_cp   = t_l; \
	(cp) += NS_INT32SZ; \
}

/*
 * ANSI C identifier hiding.
 */
#define ns_get16		__ns_get16
#define ns_get32		__ns_get32
#define ns_put16		__ns_put16
#define ns_put32		__ns_put32
#define ns_initparse		__ns_initparse
#define ns_parserr		__ns_parserr
#define	ns_sprintrr		__ns_sprintrr
#define	ns_sprintrrf		__ns_sprintrrf
#define	ns_format_ttl		__ns_format_ttl
#define	ns_parse_ttl		__ns_parse_ttl
#define	ns_name_ntop		__ns_name_ntop
#define	ns_name_pton		__ns_name_pton
#define	ns_name_unpack		__ns_name_unpack
#define	ns_name_pack		__ns_name_pack
#define	ns_name_compress	__ns_name_compress
#define	ns_name_uncompress	__ns_name_uncompress

__BEGIN_DECLS
u_int		ns_get16 __P((const u_char *));
u_long		ns_get32 __P((const u_char *));
void		ns_put16 __P((u_int, u_char *));
void		ns_put32 __P((u_long, u_char *));
int		ns_initparse __P((const u_char *, int, ns_msg *));
int		ns_parserr __P((ns_msg *, ns_sect, int, ns_rr *));
int		ns_sprintrr __P((const ns_msg *, const ns_rr *,
				 const char *, const char *, char *, size_t));
int		ns_sprintrrf __P((const u_char *, size_t, const char *,
				  ns_class, ns_type, u_long, const u_char *,
				  size_t, const char *, const char *,
				  char *, size_t));
int		ns_format_ttl __P((u_long, char *, size_t));
int		ns_parse_ttl __P((const char *, u_long *));
int		ns_name_ntop __P((const u_char *, char *, size_t));
int		ns_name_pton __P((const char *, u_char *, size_t));
int		ns_name_unpack __P((const u_char *, const u_char *,
				    const u_char *, u_char *, size_t));
int		ns_name_pack __P((const u_char *, u_char *, int,
				  const u_char **, const u_char **));
int		ns_name_uncompress __P((const u_char *, const u_char *,
					const u_char *, char *, size_t));
int		ns_name_compress __P((const char *, u_char *, size_t,
				      const u_char **, const u_char **));
int		ns_name_skip __P((const u_char **, const u_char *));
__END_DECLS

#ifdef BIND_4_COMPAT
#include <arpa/nameser_compat.h>
#endif

#endif /* !_ARPA_NAMESER_H_ */
