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
/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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
 *
 *	@(#)iso_proto.c	8.1 (Berkeley) 6/10/93
 */

/***********************************************************
		Copyright IBM Corporation 1987

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of IBM not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

IBM DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
IBM BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

******************************************************************/

/*
 * ARGO Project, Computer Sciences Dept., University of Wisconsin - Madison
 */
/* 
 * iso_proto.c : protocol switch tables in the ISO domain
 *
 * ISO protocol family includes TP, CLTP, CLNP, 8208
 * TP and CLNP are implemented here.
 */

#if	ISO
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/mbuf.h>

#include <net/radix.h>

#include <netiso/iso.h>

int clnp_output(), clnp_init(),clnp_slowtimo(),clnp_drain();
int rclnp_input(), rclnp_output(), rclnp_ctloutput(), raw_usrreq();
int	clnp_usrreq();

int	tp_ctloutput(), tpclnp_ctlinput(), tpclnp_input(), tp_usrreq();
int	tp_init(), tp_fasttimo(), tp_slowtimo(), tp_drain();
int	cons_init(), tpcons_input();

int isis_input();
int	esis_input(), esis_ctlinput(), esis_init(), esis_usrreq();
int	idrp_input(), idrp_init(), idrp_usrreq();
int	cltp_input(), cltp_ctlinput(), cltp_init(), cltp_usrreq(), cltp_output();

#if TUBA
int	tuba_usrreq(), tuba_ctloutput(), tuba_init(), tuba_tcpinput(); 
int	tuba_slowtimo(), tuba_fasttimo(); 
#endif

struct protosw isosw[] = {
/*
 *  We need a datagram entry through which net mgmt programs can get
 *	to the iso_control procedure (iso ioctls). Thus, a minimal
 *	SOCK_DGRAM interface is provided here.
 *  THIS ONE MUST BE FIRST: Kludge city : socket() says if(!proto) call
 *  pffindtype, which gets the first entry that matches the type.
 *  sigh.
 */
{ SOCK_DGRAM,	&isodomain,		ISOPROTO_CLTP,		PR_ATOMIC|PR_ADDR,
	0,			cltp_output,	0,					0,
	cltp_usrreq,
	cltp_init,	0, 				0,					0
},

/*
 *	A datagram interface for clnp cannot co-exist with TP/CLNP
 *  because CLNP has no way to discriminate incoming TP packets from
 *  packets coming in for any other higher layer protocol.
 *  Old way: set it up so that pffindproto(... dgm, clnp) fails.
 *  New way: let pffindproto work (for x.25, thank you) but create
 *  	a clnp_usrreq() that returns error on PRU_ATTACH.
 */
{SOCK_DGRAM,	&isodomain,		ISOPROTO_CLNP,		0,
 0,				clnp_output,	0,					0,
 clnp_usrreq,
 clnp_init,		0,				clnp_slowtimo, 		clnp_drain,
},

/* raw clnp */
{ SOCK_RAW,		&isodomain,		ISOPROTO_RAW,		PR_ATOMIC|PR_ADDR,
  rclnp_input,	rclnp_output,	0,					rclnp_ctloutput,
  clnp_usrreq,
  0,			0,				0,					0
},

/* ES-IS protocol */
{ SOCK_DGRAM,	&isodomain,		ISOPROTO_ESIS,		PR_ATOMIC|PR_ADDR,
  esis_input,	0,				esis_ctlinput,		0,
  esis_usrreq,
  esis_init,	0,				0,					0
},

/* ISOPROTO_INTRAISIS */
{ SOCK_DGRAM,	&isodomain,		ISOPROTO_INTRAISIS,	PR_ATOMIC|PR_ADDR,
  isis_input,	0,				0,					0,
  esis_usrreq,
  0,			0,				0,					0
},

/* ISOPROTO_IDRP */
{ SOCK_DGRAM,	&isodomain,		ISOPROTO_IDRP,		PR_ATOMIC|PR_ADDR,
  idrp_input,	0,				0,					0,
  idrp_usrreq,
  idrp_init,	0,				0,					0
},

/* ISOPROTO_TP */
{ SOCK_SEQPACKET,	&isodomain,	ISOPROTO_TP,		PR_CONNREQUIRED|PR_WANTRCVD,
  tpclnp_input,	0,				tpclnp_ctlinput,	tp_ctloutput,
  tp_usrreq,
  tp_init,		tp_fasttimo,	tp_slowtimo,		tp_drain,
},

#if TUBA
{ SOCK_STREAM,	&isodomain,		ISOPROTO_TCP,		PR_CONNREQUIRED|PR_WANTRCVD,
  tuba_tcpinput,	0,			0,					tuba_ctloutput,
  tuba_usrreq,
  tuba_init,	tuba_fasttimo,	tuba_fasttimo,		0
},
#endif

#if TPCONS
/* ISOPROTO_TP */
{ SOCK_SEQPACKET,	&isodomain,	ISOPROTO_TP0,		PR_CONNREQUIRED|PR_WANTRCVD,
  tpcons_input,		0,			0,					tp_ctloutput,
  tp_usrreq,
  cons_init,		0,			0,					0,
},
#endif

};


struct domain isodomain = {
    AF_ISO, 			/* family */
	"iso-domain", 		/* name */
	0,					/* initialize routine */
	0,					/* externalize access rights */
	0,					/* dispose of internalized rights */
	isosw,				/* protosw */
	&isosw[sizeof(isosw)/sizeof(isosw[0])], /* NPROTOSW */
	0,					/* next */
	rn_inithead,		/* rtattach */
	48,					/* rtoffset */
	sizeof(struct sockaddr_iso) /* maxkeylen */
};
#endif	/* ISO */
