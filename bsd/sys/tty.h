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
/* Copyright (c) 1997 Apple Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
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
 *	@(#)tty.h	8.6 (Berkeley) 1/21/94
 */

#ifndef _SYS_TTY_H_
#define	_SYS_TTY_H_

#include <sys/cdefs.h>

#include <sys/termios.h>
#include <sys/select.h>		/* For struct selinfo. */

#ifndef __APPLE__
/*
 * Clists are character lists, which is a variable length linked list
 * of cblocks, with a count of the number of characters in the list.
 */
struct clist {
	int	c_cc;		/* Number of characters in the clist. */
	int	c_cbcount;	/* Number of cblocks. */
	int	c_cbmax;	/* Max # cblocks allowed for this clist. */
	int	c_cbreserved;	/* # cblocks reserved for this clist. */
	char	*c_cf;		/* Pointer to the first cblock. */
	char	*c_cl;		/* Pointer to the last cblock. */
};
#else /* __APPLE__ */
/*
 * NetBSD Clists are actually ring buffers. The c_cc, c_cf, c_cl fields have
 * exactly the same behaviour as in true clists.
 * if c_cq is NULL, the ring buffer has no TTY_QUOTE functionality
 * (but, saves memory and cpu time)
 * 
 * *DON'T* play with c_cs, c_ce, c_cq, or c_cl outside tty_subr.c!!!
 */
struct clist {
	int	c_cc;		/* count of characters in queue */
	int	c_cn;		/* total ring buffer length */
	u_char	*c_cf;		/* points to first character */
	u_char	*c_cl;		/* points to next open character */
	u_char	*c_cs;		/* start of ring buffer */
	u_char	*c_ce;		/* c_ce + c_len */
	u_char	*c_cq;		/* N bits/bytes long, see tty_subr.c */
};

#ifndef TTYCLSIZE
#define TTYCLSIZE 1024
#endif

#endif /* __APPLE__ */

/*
 * Per-tty structure.
 *
 * Should be split in two, into device and tty drivers.
 * Glue could be masks of what to echo and circular buffer
 * (low, high, timeout).
 */
struct tty {
	struct	clist t_rawq;		/* Device raw input queue. */
	long	t_rawcc;		/* Raw input queue statistics. */
	struct	clist t_canq;		/* Device canonical queue. */
	long	t_cancc;		/* Canonical queue statistics. */
	struct	clist t_outq;		/* Device output queue. */
	long	t_outcc;		/* Output queue statistics. */
	int	t_line;			/* Interface to device drivers. */
	dev_t	t_dev;			/* Device. */
	int	t_state;		/* Device and driver (TS*) state. */
	int	t_flags;		/* Tty flags. */
	int     t_timeout;              /* Timeout for ttywait() */
	struct	pgrp *t_pgrp;		/* Foreground process group. */
	struct	session *t_session;	/* Enclosing session. */
	struct	selinfo t_rsel;		/* Tty read/oob select. */
	struct	selinfo t_wsel;		/* Tty write select. */
	struct	termios t_termios;	/* Termios state. */
	struct	winsize t_winsize;	/* Window size. */
					/* Start output. */
	void	(*t_oproc) __P((struct tty *));
					/* Stop output. */
	void	(*t_stop) __P((struct tty *, int));
					/* Set hardware state. */
	int	(*t_param) __P((struct tty *, struct termios *));
	void	*t_sc;			/* XXX: net/if_sl.c:sl_softc. */
	int	t_column;		/* Tty output column. */
	int	t_rocount, t_rocol;	/* Tty. */
	int	t_hiwat;		/* High water mark. */
	int	t_lowat;		/* Low water mark. */
	int	t_gen;			/* Generation number. */
};

#define	t_cc		t_termios.c_cc
#define	t_cflag		t_termios.c_cflag
#define	t_iflag		t_termios.c_iflag
#define	t_ispeed	t_termios.c_ispeed
#define	t_lflag		t_termios.c_lflag
#define	t_min		t_termios.c_min
#define	t_oflag		t_termios.c_oflag
#define	t_ospeed	t_termios.c_ospeed
#define	t_time		t_termios.c_time

#define	TTIPRI	25			/* Sleep priority for tty reads. */
#define	TTOPRI	26			/* Sleep priority for tty writes. */

/*
 * User data unfortunately has to be copied through buffers on the way to
 * and from clists.  The buffers are on the stack so their sizes must be
 * fairly small.
 */
#define	IBUFSIZ	384			/* Should be >= max value of MIN. */
#define	OBUFSIZ	100

#ifndef TTYHOG
#define	TTYHOG	1024
#endif

#ifdef KERNEL
#define	TTMAXHIWAT	roundup(2048, CBSIZE)
#define	TTMINHIWAT	roundup(100, CBSIZE)
#define	TTMAXLOWAT	256
#define	TTMINLOWAT	32
#endif /* KERNEL */

/* These flags are kept in t_state. */
#define	TS_SO_OLOWAT	0x00001		/* Wake up when output <= low water. */
#define	TS_ASYNC	0x00002		/* Tty in async I/O mode. */
#define	TS_BUSY		0x00004		/* Draining output. */
#define	TS_CARR_ON	0x00008		/* Carrier is present. */
#define	TS_FLUSH	0x00010		/* Outq has been flushed during DMA. */
#define	TS_ISOPEN	0x00020		/* Open has completed. */
#define	TS_TBLOCK	0x00040		/* Further input blocked. */
#define	TS_TIMEOUT	0x00080		/* Wait for output char processing. */
#define	TS_TTSTOP	0x00100		/* Output paused. */
#ifdef notyet
#define	TS_WOPEN	0x00200		/* Open in progress. */
#endif
#define	TS_XCLUDE	0x00400		/* Tty requires exclusivity. */

/* State for intra-line fancy editing work. */
#define	TS_BKSL		0x00800		/* State for lowercase \ work. */
#define	TS_CNTTB	0x01000		/* Counting tab width, ignore FLUSHO. */
#define	TS_ERASE	0x02000		/* Within a \.../ for PRTRUB. */
#define	TS_LNCH		0x04000		/* Next character is literal. */
#define	TS_TYPEN	0x08000		/* Retyping suspended input (PENDIN). */
#define	TS_LOCAL	(TS_BKSL | TS_CNTTB | TS_ERASE | TS_LNCH | TS_TYPEN)

/* Extras. */
#define	TS_CAN_BYPASS_L_RINT 0x010000	/* Device in "raw" mode. */
#define	TS_CONNECTED	0x020000	/* Connection open. */
#define	TS_SNOOP	0x040000	/* Device is being snooped on. */
#define	TS_SO_OCOMPLETE	0x080000	/* Wake up when output completes. */
#define	TS_ZOMBIE	0x100000	/* Connection lost. */

/* Hardware flow-control-invoked bits. */
#define	TS_CAR_OFLOW	0x200000	/* For MDMBUF (XXX handle in driver). */
#ifdef notyet
#define	TS_CTS_OFLOW	0x400000	/* For CCTS_OFLOW. */
#define	TS_DSR_OFLOW	0x800000	/* For CDSR_OFLOW. */
#endif

/* Character type information. */
#define	ORDINARY	0
#define	CONTROL		1
#define	BACKSPACE	2
#define	NEWLINE		3
#define	TAB		4
#define	VTAB		5
#define	RETURN		6

struct speedtab {
	int sp_speed;			/* Speed. */
	int sp_code;			/* Code. */
};

/* Modem control commands (driver). */
#define	DMSET		0
#define	DMBIS		1
#define	DMBIC		2
#define	DMGET		3

/* Flags on a character passed to ttyinput. */
#define	TTY_CHARMASK	0x000000ff	/* Character mask */
#define	TTY_QUOTE	0x00000100	/* Character quoted */
#define	TTY_ERRORMASK	0xff000000	/* Error mask */
#define	TTY_FE		0x01000000	/* Framing error */
#define	TTY_PE		0x02000000	/* Parity error */
#define	TTY_OE		0x04000000	/* Overrun error */
#define	TTY_BI		0x08000000	/* Break condition */

/* Is tp controlling terminal for p? */
#define	isctty(p, tp)							\
	((p)->p_session == (tp)->t_session && (p)->p_flag & P_CONTROLT)

/* Is p in background of tp? */
#define	isbackground(p, tp)						\
	(isctty((p), (tp)) && (p)->p_pgrp != (tp)->t_pgrp)

/* Unique sleep addresses. */
#define	TSA_CARR_ON(tp)		((void *)&(tp)->t_rawq)
#define	TSA_HUP_OR_INPUT(tp)	((void *)&(tp)->t_rawq.c_cf)
#define	TSA_OCOMPLETE(tp)	((void *)&(tp)->t_outq.c_cl)
#define	TSA_OLOWAT(tp)		((void *)&(tp)->t_outq)
#define	TSA_PTC_READ(tp)	((void *)&(tp)->t_outq.c_cf)
#define	TSA_PTC_WRITE(tp)	((void *)&(tp)->t_rawq.c_cl)
#define	TSA_PTS_READ(tp)	((void *)&(tp)->t_canq)

#ifdef KERNEL
__BEGIN_DECLS

#ifndef __APPLE__
extern	struct tty *constty;	/* Temporary virtual console. */

int	 b_to_q __P((char *cp, int cc, struct clist *q));
void	 catq __P((struct clist *from, struct clist *to));
void	 clist_alloc_cblocks __P((struct clist *q, int ccmax, int ccres));
void	 clist_free_cblocks __P((struct clist *q));
/* void	 clist_init __P((void)); */ /* defined in systm.h for main() */
int	 getc __P((struct clist *q));
void	 ndflush __P((struct clist *q, int cc));
int	 ndqb __P((struct clist *q, int flag));
char	*nextc __P((struct clist *q, char *cp, int *c));
int	 putc __P((int c, struct clist *q));
int	 q_to_b __P((struct clist *q, char *cp, int cc));
int	 unputc __P((struct clist *q));

int	ttcompat __P((struct tty *tp, int com, caddr_t data, int flag));
int     ttsetcompat __P((struct tty *tp, int *com, caddr_t data, struct termios *term));
#else /* __APPLE__ */
int	 b_to_q __P((u_char *cp, int cc, struct clist *q));
void	 catq __P((struct clist *from, struct clist *to));
void	 clist_init __P((void));
int	 getc __P((struct clist *q));
void	 ndflush __P((struct clist *q, int cc));
int	 ndqb __P((struct clist *q, int flag));
u_char	*firstc           __P((struct clist *clp, int *c));
u_char	*nextc __P((struct clist *q, u_char *cp, int *c));
int	 putc __P((int c, struct clist *q));
int	 q_to_b __P((struct clist *q, u_char *cp, int cc));
int	 unputc __P((struct clist *q));
int	 clalloc __P((struct clist *clp, int size, int quot));
void	 clfree __P((struct clist *clp));

#ifdef KERNEL_PRIVATE
int	ttcompat __P((struct tty *tp, u_long com, caddr_t data, int flag,
	    struct proc *p));
int	ttsetcompat __P((struct tty *tp, u_long *com, caddr_t data, struct termios *term));
#endif /* KERNEL_PRIVATE */
#endif /* __APPLE__ */

void	 termioschars __P((struct termios *t));
int	 tputchar __P((int c, struct tty *tp));
#ifndef __APPLE__
int	 ttioctl __P((struct tty *tp, int com, void *data, int flag));
#else
int	 ttioctl __P((struct tty *tp, u_long com, caddr_t data, int flag,
	    struct proc *p));
#endif
int	 ttread __P((struct tty *tp, struct uio *uio, int flag));
void	 ttrstrt __P((void *tp));
int	 ttyselect __P((struct tty *tp, int rw, struct proc *p));
int	 ttselect __P((dev_t dev, int rw, struct proc *p));
void	 ttsetwater __P((struct tty *tp));
int	 ttspeedtab __P((int speed, struct speedtab *table));
int	 ttstart __P((struct tty *tp));
void	 ttwakeup __P((struct tty *tp));
int	 ttwrite __P((struct tty *tp, struct uio *uio, int flag));
void	 ttwwakeup __P((struct tty *tp));
void	 ttyblock __P((struct tty *tp));
void	 ttychars __P((struct tty *tp));
int	 ttycheckoutq __P((struct tty *tp, int wait));
int	 ttyclose __P((struct tty *tp));
void	 ttyflush __P((struct tty *tp, int rw));
void	 ttyinfo __P((struct tty *tp));
int	 ttyinput __P((int c, struct tty *tp));
int	 ttylclose __P((struct tty *tp, int flag));
int	 ttymodem __P((struct tty *tp, int flag));
int	 ttyopen __P((dev_t device, struct tty *tp));
int	 ttysleep __P((struct tty *tp,
	    void *chan, int pri, char *wmesg, int timeout));
int	 ttywait __P((struct tty *tp));
struct tty *ttymalloc __P((void));
void     ttyfree __P((struct tty *));

__END_DECLS

#endif /* KERNEL */

#endif /* !_SYS_TTY_H_ */
