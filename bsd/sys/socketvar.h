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
/* Copyright (c) 1998, 1999 Apple Computer, Inc. All Rights Reserved */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1982, 1986, 1990, 1993
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
 *	@(#)socketvar.h	8.1 (Berkeley) 6/2/93
 */

#ifndef	_SYS_SOCKETVAR_H_
#define _SYS_SOCKETVAR_H_

#include <sys/select.h>			/* for struct selinfo */
#include <sys/queue.h>
#include <net/kext_net.h>
#include <sys/ev.h>
/*
 * Hacks to get around compiler complaints
 */
struct mbuf;
struct socket;
struct uio;
struct sockbuf;
struct sockaddr;
struct kextcb;
struct protosw;
struct sockif;
struct sockutil;

/* strings for sleep message: */
extern	char netio[], netcon[], netcls[];
#define SOCKET_CACHE_ON	
#define SO_CACHE_FLUSH_INTERVAL 1	/* Seconds */
#define SO_CACHE_TIME_LIMIT	(120/SO_CACHE_FLUSH_INTERVAL) /* Seconds */
#define SO_CACHE_MAX_FREE_BATCH	50
#define MAX_CACHED_SOCKETS	60000
#define TEMPDEBUG		0

/*
 * Kernel structure per socket.
 * Contains send and receive buffer queues,
 * handle on protocol and pointer to protocol
 * private data and error information.
 */
typedef	u_quad_t so_gen_t;

struct socket {
	int     so_zone;	/* zone we were allocated from */
	short	so_type;		/* generic type, see socket.h */
	short	so_options;		/* from socket call, see socket.h */
	short	so_linger;		/* time to linger while closing */
	short	so_state;		/* internal state flags SS_*, below */
	caddr_t	so_pcb;			/* protocol control block */
	struct	protosw *so_proto;	/* protocol handle */
/*
 * Variables for connection queueing.
 * Socket where accepts occur is so_head in all subsidiary sockets.
 * If so_head is 0, socket is not related to an accept.
 * For head socket so_q0 queues partially completed connections,
 * while so_q is a queue of connections ready to be accepted.
 * If a connection is aborted and it has so_head set, then
 * it has to be pulled out of either so_q0 or so_q.
 * We allow connections to queue up based on current queue lengths
 * and limit on number of queued connections for this socket.
 */
	struct	socket *so_head;	/* back pointer to accept socket */
	TAILQ_HEAD(, socket) so_incomp;	/* queue of partial unaccepted connections */
	TAILQ_HEAD(, socket) so_comp;	/* queue of complete unaccepted connections */
	TAILQ_ENTRY(socket) so_list;	/* list of unaccepted connections */
	short	so_qlen;		/* number of unaccepted connections */
	short	so_incqlen;		/* number of unaccepted incomplete
					   connections */
	short	so_qlimit;		/* max number queued connections */
	short	so_timeo;		/* connection timeout */
	u_short	so_error;		/* error affecting connection */
	pid_t	so_pgid;		/* pgid for signals */
	u_long	so_oobmark;		/* chars to oob mark */
/*
 * Variables for socket buffering.
 */
	struct	sockbuf {
		u_long	sb_cc;		/* actual chars in buffer */
		u_long	sb_hiwat;	/* max actual char count */
		u_long	sb_mbcnt;	/* chars of mbufs used */
		u_long	sb_mbmax;	/* max chars of mbufs to use */
		long	sb_lowat;	/* low water mark */
		struct	mbuf *sb_mb;	/* the mbuf chain */
	        struct  socket *sb_so;  /* socket back ptr */
		struct	selinfo sb_sel;	/* process selecting read/write */
		short	sb_flags;	/* flags, see below */
		short	sb_timeo;	/* timeout for read/write */
		void	*reserved1;	/* for future use if needed */
		void	*reserved2;
	} so_rcv, so_snd;
#define	SB_MAX		(256*1024)	/* default for max chars in sockbuf */
#define	SB_LOCK		0x01		/* lock on data queue */
#define	SB_WANT		0x02		/* someone is waiting to lock */
#define	SB_WAIT		0x04		/* someone is waiting for data/space */
#define	SB_SEL		0x08		/* someone is selecting */
#define	SB_ASYNC	0x10		/* ASYNC I/O, need signals */
#define	SB_NOTIFY	(SB_WAIT|SB_SEL|SB_ASYNC)
#define	SB_UPCALL	0x20		/* someone wants an upcall */
#define	SB_NOINTR	0x40		/* operations not interruptible */
#define SB_RECV		0x8000		/* this is rcv sb */

	caddr_t	so_tpcb;		/* Wisc. protocol control block XXX */
	void	(*so_upcall) __P((struct socket *so, caddr_t arg, int waitf));
	caddr_t	so_upcallarg;		/* Arg for above */
	uid_t	so_uid;			/* who opened the socket */
	/* NB: generation count must not be first; easiest to make it last. */
	so_gen_t so_gencnt;		/* generation count */
	TAILQ_HEAD(,eventqelt) so_evlist;
	int	cached_in_sock_layer;	/* Is socket bundled with pcb/pcb.inp_ppcb? */
	struct	socket	*cache_next;
	struct	socket	*cache_prev;
	u_long		cache_timestamp;
	caddr_t		so_saved_pcb;	/* Saved pcb when cacheing */
	struct	mbuf *so_temp;		/* Holding area for outbound frags */
	/* Plug-in support - make the socket interface overridable */
	struct	mbuf *so_tail;
	struct	kextcb *so_ext;		/* NKE hook */
	void	*reserved1;		/* for future use if needed */
	void	*reserved2;
	void	*reserved3;
	void	*reserved4;
};

/*
 * Socket state bits.
 */
#define	SS_NOFDREF		0x001	/* no file table ref any more */
#define	SS_ISCONNECTED		0x002	/* socket connected to a peer */
#define	SS_ISCONNECTING		0x004	/* in process of connecting to peer */
#define	SS_ISDISCONNECTING	0x008	/* in process of disconnecting */
#define	SS_CANTSENDMORE		0x010	/* can't send more data to peer */
#define	SS_CANTRCVMORE		0x020	/* can't receive more data from peer */
#define	SS_RCVATMARK		0x040	/* at mark on input */

#define	SS_PRIV			0x080	/* privileged for broadcast, raw... */
#define	SS_NBIO			0x100	/* non-blocking ops */
#define	SS_ASYNC		0x200	/* async i/o notify */
#define	SS_ISCONFIRMING		0x400	/* deciding to accept connection req */
#define	SS_INCOMP		0x800	/* Unaccepted, incomplete connection */
#define	SS_COMP			0x1000	/* unaccepted, complete connection */

/*
 * Externalized form of struct socket used by the sysctl(3) interface.
 */
struct	xsocket {
	size_t	xso_len;	/* length of this structure */
	struct	socket *xso_so;	/* makes a convenient handle sometimes */
	short	so_type;
	short	so_options;
	short	so_linger;
	short	so_state;
	caddr_t	so_pcb;		/* another convenient handle */
	int	xso_protocol;
	int	xso_family;
	short	so_qlen;
	short	so_incqlen;
	short	so_qlimit;
	short	so_timeo;
	u_short	so_error;
	pid_t	so_pgid;
	u_long	so_oobmark;
	struct	xsockbuf {
		u_long	sb_cc;
		u_long	sb_hiwat;
		u_long	sb_mbcnt;
		u_long	sb_mbmax;
		long	sb_lowat;
		short	sb_flags;
		short	sb_timeo;
	} so_rcv, so_snd;
	uid_t	so_uid;		/* XXX */
};

/*
 * Macros for sockets and socket buffering.
 */
#define sbtoso(sb) (sb->sb_so)


/*
 * Socket extension mechanism: control block hooks:
 * This is the "head" of any control block for an extenstion
 * Note: we separate intercept function dispatch vectors from
 *  the NFDescriptor to permit selective replacement during
 *  operation, e.g., to disable some functions.
 */
struct kextcb
{	struct kextcb *e_next;		/* Next kext control block */
	void *e_fcb;			/* Real filter control block */
	struct NFDescriptor *e_nfd;	/* NKE Descriptor */
	/* Plug-in support - intercept functions */
	struct sockif *e_soif;		/* Socket functions */
	struct sockutil *e_sout;	/* Sockbuf utility functions */
};
#define EXT_NULL	0x0		/* STATE: Not in use */
#define sotokextcb(so) (so ? so->so_ext : 0)

#ifdef KERNEL
/*
 * Argument structure for sosetopt et seq.  This is in the KERNEL
 * section because it will never be visible to user code.
 */
enum sopt_dir { SOPT_GET, SOPT_SET };
struct sockopt {
	enum	sopt_dir sopt_dir; /* is this a get or a set? */
	int	sopt_level;	/* second arg of [gs]etsockopt */
	int	sopt_name;	/* third arg of [gs]etsockopt */
	void   *sopt_val;	/* fourth arg of [gs]etsockopt */
	size_t	sopt_valsize;	/* (almost) fifth arg of [gs]etsockopt */
	struct	proc *sopt_p;	/* calling process or null if kernel */
};

#if SENDFILE

struct sf_buf {
	SLIST_ENTRY(sf_buf) free_list;	/* list of free buffer slots */
	int		refcnt;		/* reference count */
	struct		vm_page *m;	/* currently mapped page */
	vm_offset_t	kva;		/* va of mapping */
};

#endif

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_PCB);
MALLOC_DECLARE(M_SONAME);
#endif

extern int	maxsockets;
extern u_long	sb_max;
extern int socket_zone;
extern so_gen_t so_gencnt;

struct file;
struct filedesc;
struct mbuf;
struct sockaddr;
struct stat;
struct ucred;
struct uio;

/*
 * File operations on sockets.
 */
int	soo_read __P((struct file *fp, struct uio *uio, struct ucred *cred));
int	soo_write __P((struct file *fp, struct uio *uio, struct ucred *cred));
int	soo_ioctl __P((struct file *fp, u_long cmd, caddr_t data,
	    struct proc *p));
int	soo_select __P((struct file *fp, int which, void * wql, struct proc *p));
int	soo_stat __P((struct socket *so, struct stat *ub));

int 	soo_close __P((struct file *fp, struct proc *p));


/*
 * From uipc_socket and friends
 */
struct	sockaddr *dup_sockaddr __P((struct sockaddr *sa, int canwait));
int	getsock __P((struct filedesc *fdp, int fd, struct file **fpp));
int	sockargs __P((struct mbuf **mp, caddr_t buf, int buflen, int type));
int	getsockaddr __P((struct sockaddr **namp, caddr_t uaddr, size_t len));
void	sbappend __P((struct sockbuf *sb, struct mbuf *m));
int	sbappendaddr __P((struct sockbuf *sb, struct sockaddr *asa,
	    struct mbuf *m0, struct mbuf *control));
int	sbappendcontrol __P((struct sockbuf *sb, struct mbuf *m0,
	    struct mbuf *control));
void	sbappendrecord __P((struct sockbuf *sb, struct mbuf *m0));
void	sbcheck __P((struct sockbuf *sb));
void	sbcompress __P((struct sockbuf *sb, struct mbuf *m, struct mbuf *n));
struct mbuf *
	sbcreatecontrol __P((caddr_t p, int size, int type, int level));
void	sbdrop __P((struct sockbuf *sb, int len));
void	sbdroprecord __P((struct sockbuf *sb));
void	sbflush __P((struct sockbuf *sb));
void	sbinsertoob __P((struct sockbuf *sb, struct mbuf *m0));
void	sbrelease __P((struct sockbuf *sb));
int	sbreserve __P((struct sockbuf *sb, u_long cc));
void	sbtoxsockbuf __P((struct sockbuf *sb, struct xsockbuf *xsb));
int	sbwait __P((struct sockbuf *sb));
int	sb_lock __P((struct sockbuf *sb));
int	soabort __P((struct socket *so));
int	soaccept __P((struct socket *so, struct sockaddr **nam));
struct	socket *soalloc __P((int waitok, int dom, int type));
int	sobind __P((struct socket *so, struct sockaddr *nam));
void	socantrcvmore __P((struct socket *so));
void	socantsendmore __P((struct socket *so));
int	soclose __P((struct socket *so));
int	soconnect __P((struct socket *so, struct sockaddr *nam));
int	soconnect2 __P((struct socket *so1, struct socket *so2));
int	socreate __P((int dom, struct socket **aso, int type, int proto));
void	sodealloc __P((struct socket *so));
int	sodisconnect __P((struct socket *so));
void	sofree __P((struct socket *so));
int	sogetopt __P((struct socket *so, struct sockopt *sopt));
void	sohasoutofband __P((struct socket *so));
void	soisconnected __P((struct socket *so));
void	soisconnecting __P((struct socket *so));
void	soisdisconnected __P((struct socket *so));
void	soisdisconnecting __P((struct socket *so));
int	solisten __P((struct socket *so, int backlog));
struct socket *
	sodropablereq __P((struct socket *head));
struct socket *
	sonewconn __P((struct socket *head, int connstatus));
int	sooptcopyin __P((struct sockopt *sopt, void *buf, size_t len,
			 size_t minlen));
int	sooptcopyout __P((struct sockopt *sopt, void *buf, size_t len));
int	sopoll __P((struct socket *so, int events, struct ucred *cred, void *wql));
int	soreceive __P((struct socket *so, struct sockaddr **paddr,
		       struct uio *uio, struct mbuf **mp0,
		       struct mbuf **controlp, int *flagsp));
int	soreserve __P((struct socket *so, u_long sndcc, u_long rcvcc));
void	sorflush __P((struct socket *so));
int	sosend __P((struct socket *so, struct sockaddr *addr, struct uio *uio,
		    struct mbuf *top, struct mbuf *control, int flags));

int	sosetopt __P((struct socket *so, struct sockopt *sopt));


int	soshutdown __P((struct socket *so, int how));
void	sotoxsocket __P((struct socket *so, struct xsocket *xso));
void	sowakeup __P((struct socket *so, struct sockbuf *sb));
int	sb_notify __P((struct sockbuf *sb));
long	sbspace	__P((struct sockbuf *sb));
int	sosendallatonce __P((struct socket *so));
int	soreadable __P((struct socket *so));
int	sowriteable __P((struct socket *so));
void	sballoc __P((struct sockbuf *sb, struct mbuf *m));
void	sbfree __P((struct sockbuf *sb, struct mbuf *m));
int	sblock __P((struct sockbuf *sb, int wf));
void	sbunlock __P((struct sockbuf *sb));
void	sorwakeup __P((struct socket * so));
void	sowwakeup __P((struct socket * so));












#endif /* KERNEL */
#endif /* !_SYS_SOCKETVAR_H_ */
