/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1994 Gordon Ross, Adam Glass 
 * Copyright (c) 1992 Regents of the University of California.
 * All rights reserved.
 *
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66 and
 * contributed to Berkeley.
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
 *	California, Lawrence Berkeley Laboratory and its contributors.
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
 */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/reboot.h>

#include <net/if.h>
#include <netinet/in.h>

#include <nfs/rpcv2.h>
#include <nfs/krpc.h>

/*
 * Kernel support for Sun RPC
 *
 * Used currently for bootstrapping in nfs diskless configurations.
 * 
 * Note: will not work on variable-sized rpc args/results.
 *       implicit size-limit of an mbuf.
 */

/*
 * Generic RPC headers
 */

struct auth_info {
	u_int32_t	rp_atype;	/* auth type */
	u_int32_t	rp_alen;	/* auth length */
};

struct rpc_call {
	u_int32_t	rp_xid;		/* request transaction id */
	int32_t 	rp_direction;	/* call direction (0) */
	u_int32_t	rp_rpcvers;	/* rpc version (2) */
	u_int32_t	rp_prog;	/* program */
	u_int32_t	rp_vers;	/* version */
	u_int32_t	rp_proc;	/* procedure */
	struct	auth_info rp_auth;
	struct	auth_info rp_verf;
};

struct rpc_reply {
	u_int32_t rp_xid;		/* request transaction id */
	int32_t  rp_direction;		/* call direction (1) */
	int32_t  rp_astatus;		/* accept status (0: accepted) */
	union {
		u_int32_t rpu_errno;
		struct {
			struct auth_info rp_auth;
			u_int32_t	rp_rstatus;
		} rpu_ok;
	} rp_u;
};

#define MIN_REPLY_HDR 16	/* xid, dir, astat, errno */

/*
 * What is the longest we will wait before re-sending a request?
 * Note this is also the frequency of "RPC timeout" messages.
 * The re-send loop count sup linearly to this maximum, so the
 * first complaint will happen after (1+2+3+4+5)=15 seconds.
 */
#define	MAX_RESEND_DELAY 5	/* seconds */

/* copied over from nfs_boot.c for printf format. could put in .h file... */
#define IP_FORMAT       "%d.%d.%d.%d"
#define IP_CH(ip)       ((u_char *)ip)
#define IP_LIST(ip)     IP_CH(ip)[0],IP_CH(ip)[1],IP_CH(ip)[2],IP_CH(ip)[3]


/*
 * Call portmap to lookup a port number for a particular rpc program
 * Returns non-zero error on failure.
 */
int
krpc_portmap(sin,  prog, vers, portp)
	struct sockaddr_in *sin;		/* server address */
	u_int prog, vers;	/* host order */
	u_int16_t *portp;	/* network order */
{
	struct sdata {
		u_int32_t prog;		/* call program */
		u_int32_t vers;		/* call version */
		u_int32_t proto;	/* call protocol */
		u_int32_t port;		/* call port (unused) */
	} *sdata;
	struct rdata {
		u_int16_t pad;
		u_int16_t port;
	} *rdata;
	struct mbuf *m;
	int error;

	/* The portmapper port is fixed. */
	if (prog == PMAPPROG) {
		*portp = htons(PMAPPORT);
		return 0;
	}

	m = m_gethdr(M_WAIT, MT_DATA);
	if (m == NULL)
		return ENOBUFS;
	m->m_len = sizeof(*sdata);
	m->m_pkthdr.len = m->m_len;
	sdata = mtod(m, struct sdata *);

	/* Do the RPC to get it. */
	sdata->prog = htonl(prog);
	sdata->vers = htonl(vers);
	sdata->proto = htonl(IPPROTO_UDP);
	sdata->port = 0;

	sin->sin_port = htons(PMAPPORT);
	error = krpc_call(sin, PMAPPROG, PMAPVERS,
					  PMAPPROC_GETPORT, &m, NULL);
	if (error) 
		return error;

	rdata = mtod(m, struct rdata *);
	*portp = rdata->port;

	m_freem(m);
	return 0;
}

/*
 * Do a remote procedure call (RPC) and wait for its reply.
 * If from_p is non-null, then we are doing broadcast, and
 * the address from whence the response came is saved there.
 */
int
krpc_call(sa, prog, vers, func, data, from_p)
	struct sockaddr_in *sa;
	u_int prog, vers, func;
	struct mbuf **data;	/* input/output */
	struct sockaddr_in **from_p;	/* output */
{
	struct socket *so;
	struct sockaddr_in *sin;
	struct mbuf *m, *nam, *mhead, *mhck;
	struct rpc_call *call;
	struct rpc_reply *reply;
	struct uio auio;
	int error, rcvflg, timo, secs, len;
	static u_int32_t xid = ~0xFF;
	u_int16_t tport;
	struct sockopt sopt;

	/*
	 * Validate address family.
	 * Sorry, this is INET specific...
	 */
	if (sa->sin_family != AF_INET)
		return (EAFNOSUPPORT);

	/* Free at end if not null. */
	nam = mhead = NULL;
	if (from_p)
	    *from_p = 0;

	/*
	 * Create socket and set its recieve timeout.
	 */
	if ((error = socreate(AF_INET, &so, SOCK_DGRAM, 0)))
		goto out;

	{
		struct timeval tv;

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		bzero(&sopt, sizeof sopt);
		sopt.sopt_level = SOL_SOCKET;
		sopt.sopt_name = SO_RCVTIMEO;
		sopt.sopt_val = &tv;
		sopt.sopt_valsize = sizeof tv;

		if (error = sosetopt(so, &sopt))
		    goto out;

	}

	/*
	 * Enable broadcast if necessary.
	 */

	if (from_p) {
		int on = 1;
		sopt.sopt_name = SO_BROADCAST;
		sopt.sopt_val = &on;
		sopt.sopt_valsize = sizeof on;
		if (error = sosetopt(so, &sopt))
			goto out;
	}

	/*
	 * Bind the local endpoint to a reserved port,
	 * because some NFS servers refuse requests from
	 * non-reserved (non-privileged) ports.
	 */
	m = m_getclr(M_WAIT, MT_SONAME);
	sin = mtod(m, struct sockaddr_in *);
	sin->sin_len = m->m_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = INADDR_ANY;
	tport = IPPORT_RESERVED;
	do {
		tport--;
		sin->sin_port = htons(tport);
		error = sobind(so, mtod(m, struct sockaddr *));
	} while (error == EADDRINUSE &&
			 tport > IPPORT_RESERVED / 2);
	m_freem(m);
	if (error) {
		printf("bind failed\n");
		goto out;
	}

	/*
	 * Setup socket address for the server.
	 */
	nam = m_get(M_WAIT, MT_SONAME);
	if (nam == NULL) {
		error = ENOBUFS;
		goto out;
	}
	sin = mtod(nam, struct sockaddr_in *);
	bcopy((caddr_t)sa, (caddr_t)sin, (nam->m_len = sa->sin_len));

	/*
	 * Prepend RPC message header.
	 */
	m = *data;
	*data = NULL;
#if	DIAGNOSTIC
	if ((m->m_flags & M_PKTHDR) == 0)
		panic("krpc_call: send data w/o pkthdr");
	if (m->m_pkthdr.len < m->m_len)
		panic("krpc_call: pkthdr.len not set");
#endif
	mhead = m_prepend(m, sizeof(*call), M_WAIT);
	if (mhead == NULL) {
		error = ENOBUFS;
		goto out;
	}
	mhead->m_pkthdr.len += sizeof(*call);
	mhead->m_pkthdr.rcvif = NULL;

	/*
	 * Fill in the RPC header
	 */
	call = mtod(mhead, struct rpc_call *);
	bzero((caddr_t)call, sizeof(*call));
	xid++;
	call->rp_xid = htonl(xid);
	/* call->rp_direction = 0; */
	call->rp_rpcvers = htonl(2);
	call->rp_prog = htonl(prog);
	call->rp_vers = htonl(vers);
	call->rp_proc = htonl(func);
	/* call->rp_auth = 0; */
	/* call->rp_verf = 0; */

	/*
	 * Send it, repeatedly, until a reply is received,
	 * but delay each re-send by an increasing amount.
	 * If the delay hits the maximum, start complaining.
	 */
	timo = 0;
	for (;;) {
		/* Send RPC request (or re-send). */
		m = m_copym(mhead, 0, M_COPYALL, M_WAIT);
		if (m == NULL) {
			error = ENOBUFS;
			goto out;
		}
		error = sosend(so, mtod(nam, struct sockaddr *), NULL, m, NULL, 0);
		if (error) {
			printf("krpc_call: sosend: %d\n", error);
			goto out;
		}
		m = NULL;

		/* Determine new timeout. */
		if (timo < MAX_RESEND_DELAY)
			timo++;
            	else
           		printf("RPC timeout for server " IP_FORMAT "\n",
				IP_LIST(&(sin->sin_addr.s_addr)));

		/*
		 * Wait for up to timo seconds for a reply.
		 * The socket receive timeout was set to 1 second.
		 */
		secs = timo;
		while (secs > 0) {
			if ((from_p) && (*from_p)){
				FREE(*from_p, M_SONAME);
				*from_p = NULL;
			}

			if (m) {
				m_freem(m);
				m = NULL;
			}
			auio.uio_resid = len = 1<<16;
			rcvflg = 0;

			error = soreceive(so, (struct sockaddr **) from_p, &auio, &m, NULL, &rcvflg);

			if (error == EWOULDBLOCK) {
				secs--;
				continue;
			}
			if (error)
				goto out;
			len -= auio.uio_resid;

			/* Does the reply contain at least a header? */
			if (len < MIN_REPLY_HDR)
				continue;
			if (m->m_len < MIN_REPLY_HDR)
				continue;
			reply = mtod(m, struct rpc_reply *);

			/* Is it the right reply? */
			if (reply->rp_direction != htonl(RPC_REPLY))
				continue;

			if (reply->rp_xid != htonl(xid))
				continue;

			/* Was RPC accepted? (authorization OK) */
			if (reply->rp_astatus != 0) {
				error = ntohl(reply->rp_u.rpu_errno);
				printf("rpc denied, error=%d\n", error);
				/* convert rpc error to errno */
				switch (error) {
				case RPC_MISMATCH:
					error = ERPCMISMATCH;
					break;
				case RPC_AUTHERR:
					error = EAUTH;
					break;
				}
				goto out;
			}

			/* Did the call succeed? */
			if ((error = ntohl(reply->rp_u.rpu_ok.rp_rstatus)) != 0) {
				printf("rpc status=%d\n", error);
				/* convert rpc error to errno */
				switch (error) {
				case RPC_PROGUNAVAIL:
					error = EPROGUNAVAIL;
					break;
				case RPC_PROGMISMATCH:
					error = EPROGMISMATCH;
					break;
				case RPC_PROCUNAVAIL:
					error = EPROCUNAVAIL;
					break;
				case RPC_GARBAGE:
					error = EINVAL;
					break;
				case RPC_SYSTEM_ERR:
					error = EIO;
					break;
				}
				goto out;
			}

			goto gotreply;	/* break two levels */

		} /* while secs */
	} /* forever send/receive */

	error = ETIMEDOUT;
	goto out;

 gotreply:

	/*
	 * Pull as much as we can into first mbuf, to make
	 * result buffer contiguous.  Note that if the entire
	 * result won't fit into one mbuf, you're out of luck.
	 * XXX - Should not rely on making the entire reply
	 * contiguous (fix callers instead). -gwr
	 */
#if	DIAGNOSTIC
	if ((m->m_flags & M_PKTHDR) == 0)
		panic("krpc_call: received pkt w/o header?");
#endif
	len = m->m_pkthdr.len;
	if (m->m_len < len) {
		m = m_pullup(m, len);
		if (m == NULL) {
			error = ENOBUFS;
			goto out;
		}
		reply = mtod(m, struct rpc_reply *);
	}

	/*
	 * Strip RPC header
	 */
	len = sizeof(*reply);
	if (reply->rp_u.rpu_ok.rp_auth.rp_atype != 0) {
		len += ntohl(reply->rp_u.rpu_ok.rp_auth.rp_alen);
		len = (len + 3) & ~3; /* XXX? */
	}
	m_adj(m, len);

	/* result */
	*data = m;
 out:
	if (nam) m_freem(nam);
	if (mhead) m_freem(mhead);
	soclose(so);
	return error;
}
