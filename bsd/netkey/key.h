/*	$KAME: key.h,v 1.11 2000/03/25 07:24:12 sumikawa Exp $	*/

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

#ifndef _NETKEY_KEY_H_
#define _NETKEY_KEY_H_

#ifdef KERNEL

extern struct key_cb key_cb;

struct secpolicy;
struct secpolicyindex;
struct ipsecrequest;
struct secasvar;
struct sockaddr;
struct socket;
struct sadb_msg;
struct sadb_x_policy;

extern struct secpolicy *key_allocsp __P((struct secpolicyindex *spidx,
					u_int dir));
extern int key_checkrequest
	__P((struct ipsecrequest *isr, struct secasindex *saidx));
extern struct secasvar *key_allocsa __P((u_int family, caddr_t src, caddr_t dst,
					u_int proto, u_int32_t spi));
extern void key_freesp __P((struct secpolicy *sp));
extern void key_freeso __P((struct socket *so));
extern void key_freesav __P((struct secasvar *sav));
extern struct secpolicy *key_newsp __P((void));
extern struct secpolicy *key_msg2sp __P((struct sadb_x_policy *xpl0,
	size_t len, int *error));
extern struct mbuf *key_sp2msg __P((struct secpolicy *sp));
extern int key_ismyaddr __P((u_int family, caddr_t addr));
extern void key_timehandler __P((void));
extern void key_srandom __P((void));
extern void key_freereg __P((struct socket *so));
extern int key_parse __P((struct sadb_msg **msgp, struct socket *so,
			int *targetp));
extern void key_init __P((void));
extern int key_checktunnelsanity __P((struct secasvar *sav, u_int family,
					caddr_t src, caddr_t dst));
extern void key_sa_recordxfer __P((struct secasvar *sav, struct mbuf *m));
extern void key_sa_routechange __P((struct sockaddr *dst));

#if MALLOC_DECLARE
MALLOC_DECLARE(M_SECA);
#endif /* MALLOC_DECLARE */

#if defined(__bsdi__) || defined(__NetBSD__)
extern int key_sysctl __P((int *, u_int, void *, size_t *, void *, size_t));
#endif

#endif /* defined(KERNEL) */
#endif /* _NETKEY_KEY_H_ */
