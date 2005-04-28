/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*	$KAME: if_gif.h,v 1.7 2000/02/22 14:01:46 itojun Exp $	*/

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

/*
 * if_gif.h
 */

#ifndef _NET_IF_GIF_H_
#define _NET_IF_GIF_H_
#include <sys/appleapiopts.h>

#include <netinet/in.h>
/* xxx sigh, why route have struct route instead of pointer? */

#ifdef KERNEL_PRIVATE
struct encaptab;

struct gif_softc {
	struct ifnet	gif_if;	   /* common area - must be at the top */
	struct sockaddr	*gif_psrc; /* Physical src addr */
	struct sockaddr	*gif_pdst; /* Physical dst addr */
#ifdef __APPLE__
	u_long	gif_proto; /* dlil protocol attached */
#endif
	union {
		struct route  gifscr_ro;    /* xxx */
#if INET6
		struct route_in6 gifscr_ro6; /* xxx */
#endif
	} gifsc_gifscr;
	int		gif_flags;
	int		gif_called;
	const struct encaptab *encap_cookie4;
	const struct encaptab *encap_cookie6;
	TAILQ_ENTRY(gif_softc) gif_link; /* all gif's are linked */
};

#define gif_ro gifsc_gifscr.gifscr_ro
#if INET6
#define gif_ro6 gifsc_gifscr.gifscr_ro6
#endif

#endif /* KERNEL_PRIVATE */

#define GIF_MTU		(1280)	/* Default MTU */
#define	GIF_MTU_MIN	(1280)	/* Minimum MTU */
#define	GIF_MTU_MAX	(8192)	/* Maximum MTU */

#ifdef KERNEL_PRIVATE

/* Prototypes */
int gif_input(struct mbuf *, char*, struct ifnet *, u_long, int);
int gif_output(struct ifnet *, struct mbuf *,
		    struct sockaddr *, struct rtentry *);
int gif_ioctl(struct ifnet *, u_long, void*);

#endif /* KERNEL_PRIVATE */
#endif /* _NET_IF_GIF_H_ */
