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
/* Copyright (C) 1999 Apple Computer, Inc.  */
/*
 * Support for network filter kernel extensions
 * Justin C. Walker, 990319
 */
#ifndef NET_KEXT_NET_H
#define NET_KEXT_NET_H

#include <sys/queue.h>
#include <sys/socketvar.h>

struct mbuf;
struct socket;
struct uio;
struct sockbuf;
struct sockaddr;
struct kextcb;
struct protosw;
struct sockif;
struct sockutil;
struct sockopt;

/*
 * This structure gives access to the functionality of the filter.
 * The kextcb provides the link from the socket structure.
 */
struct NFDescriptor
{	TAILQ_ENTRY(NFDescriptor) nf_next;	/* protosw chain */
	TAILQ_ENTRY(NFDescriptor) nf_list;	/* descriptor list */
	unsigned int nf_handle;			/* Identifier */
	int nf_flags;
	/* Dispatch for PF_FILTER control */
	int (*nf_connect)();			/* Make contact */
	void (*nf_disconnect)();		/* Break contact */
	int (*nf_read)();			/* Get data from filter */
	int (*nf_write)();			/* Send data to filter */
	int (*nf_get)();			/* Get filter config */
	int (*nf_set)();			/* Set filter config */
	/*
	 * Socket function dispatch vectors - copied to kextcb
	 *  during socreate()
	 */
	struct  sockif *nf_soif;		/* Socket functions */
	struct	sockutil *nf_soutil;		/* Sockbuf utility functions */
	u_long	reserved[4];			/* for future use if needed */
};

#define NFD_GLOBAL	0x01
#define NFD_PROG	0x02
#define NFD_VISIBLE	0x80000000

#define NFF_BEFORE		0x01
#define NFF_AFTER		0x02

#ifdef KERNEL
/* How to register: filter, insert location, target protosw, flags */
extern int register_sockfilter(struct NFDescriptor *,
			       struct NFDescriptor *,
			       struct protosw *, int);
/* How to unregister: filter, original protosw, flags */
extern int unregister_sockfilter(struct NFDescriptor *, struct protosw *, int);

TAILQ_HEAD(nf_list, NFDescriptor);

extern struct nf_list nf_list;
#endif

#define NKE_OK 0
#define NKE_REMOVE -1

/*
 * Interface structure for inserting an installed socket NKE into an
 *  existing socket.
 * 'handle' is the NKE to be inserted, 'where' is an insertion point,
 *  and flags dictate the position of the to-be-inserted NKE relative to
 *  the 'where' NKE.  If the latter is NULL, the flags indicate "first"
 *  or "last"
 */
struct so_nke
{	unsigned int nke_handle;
	unsigned int nke_where;
	int nke_flags; /* NFF_BEFORE, NFF_AFTER: net/kext_net.h */
	unsigned long reserved[4];	/* for future use */
};

/*
 * sockif:
 * Contains socket interface:
 *  dispatch vector abstracting the interface between protocols and
 *  the socket layer.
 * TODO: add sf_sosense()
 */
struct sockif
{	int (*sf_soabort)(struct socket *, struct kextcb *);
	int (*sf_soaccept)(struct socket *, struct sockaddr **,
			   struct kextcb *);
	int (*sf_sobind)(struct socket *, struct sockaddr *, struct kextcb *);
	int (*sf_soclose)(struct socket *, struct kextcb *);
	int (*sf_soconnect)(struct socket *, struct sockaddr *,
			    struct kextcb *);
	int (*sf_soconnect2)(struct socket *, struct socket *,
			     struct kextcb *);
	int (*sf_socontrol)(struct socket *, struct sockopt *,
			    struct kextcb *);
	int (*sf_socreate)(struct socket *, struct protosw *, struct kextcb *);
	int (*sf_sodisconnect)(struct socket *, struct kextcb *);
	int (*sf_sofree)(struct socket *, struct kextcb *);
	int (*sf_sogetopt)(struct socket *, int, int, struct mbuf **,
			   struct kextcb *);
	int (*sf_sohasoutofband)(struct socket *, struct kextcb *);
	int (*sf_solisten)(struct socket *, struct kextcb *);
	int (*sf_soreceive)(struct socket *, struct sockaddr **, struct uio **,
			    struct mbuf **, struct mbuf **, int *,
			    struct kextcb *);
	int (*sf_sorflush)(struct socket *, struct kextcb *);
	int (*sf_sosend)(struct socket *, struct sockaddr **, struct uio **,
			 struct mbuf **, struct mbuf **, int *,
			 struct kextcb *);
	int (*sf_sosetopt)(struct socket *, int, int, struct mbuf *,
			   struct kextcb *);
	int (*sf_soshutdown)(struct socket *, int, struct kextcb *);
	/* Calls sorwakeup() */
	int (*sf_socantrcvmore)(struct socket *, struct kextcb *);
	/* Calls sowwakeup() */
	int (*sf_socantsendmore)(struct socket *, struct kextcb *);
	/* Calls soqinsque(), sorwakeup(), sowwakeup() */
	int (*sf_soisconnected)(struct socket *, struct kextcb *);
	int (*sf_soisconnecting)(struct socket *, struct kextcb *);
	/* Calls sowwakeup(), sorwakeup() */
	int (*sf_soisdisconnected)(struct socket *, struct kextcb *);
	/* Calls sowwakeup(), sorwakeup() */
	int (*sf_soisdisconnecting)(struct socket *, struct kextcb *);
	/* Calls soreserve(), soqinsque(), soqremque(), sorwakeup() */
	struct socket *(*sf_sonewconn1)(struct socket *, int, struct kextcb *);
	int (*sf_soqinsque)(struct socket *, struct socket *, int,
			     struct kextcb *);
	int (*sf_soqremque)(struct socket *, int, struct kextcb *);
	int (*sf_soreserve)(struct socket *, u_long, u_long, struct kextcb *);
	int (*sf_sowakeup)(struct socket *, struct sockbuf *,
			    struct kextcb *);
	u_long	reserved[4];
};


/*
 * sockutil:
 * Contains the utility functions for socket layer access
 */
struct sockutil
{	/* Sleeps if locked */
	int (*su_sb_lock)(struct sockbuf *, struct kextcb *);
	/* Conditionally calls sbappendrecord, Calls sbcompress */
	int (*su_sbappend)(struct sockbuf *, struct mbuf *, struct kextcb *);
	/* Calls sbspace(), sballoc() */
	int (*su_sbappendaddr)(struct sockbuf *, struct sockaddr *,
			       struct mbuf *, struct mbuf *, struct kextcb *);
	/* Calls sbspace(), sballoc() */
	int (*su_sbappendcontrol)(struct sockbuf *, struct mbuf *,
				  struct mbuf *, struct kextcb *);
	/* Calls sballoc(), sbcompress() */
	int (*su_sbappendrecord)(struct sockbuf *, struct mbuf *,
				  struct kextcb *);
	/* Calls sballoc() */
	int (*su_sbcompress)(struct sockbuf *, struct mbuf *, struct mbuf *,
			      struct kextcb *);
	/* Calls sbfree() */
	int (*su_sbdrop)(struct sockbuf *, int, struct kextcb *);
	/* Calls sbfree() */
	int (*su_sbdroprecord)(struct sockbuf *, struct kextcb *);
	/* Calls sbdrop() */
	int (*su_sbflush)(struct sockbuf *, struct kextcb *);
	/* Calls sballoc(), sbcompress() */
	int (*su_sbinsertoob)(struct sockbuf *, struct mbuf *,
			       struct kextcb *);
	/* Calls sbflush() */
	int (*su_sbrelease)(struct sockbuf *, struct kextcb *);
	int (*su_sbreserve)(struct sockbuf *, u_long, struct kextcb *);
	/* Calls tsleep() */
	int (*su_sbwait)(struct sockbuf *, struct kextcb *);
	u_long	reserved[4];
};

#endif
