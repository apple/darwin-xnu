/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1990, 1991, 1993
 *      The Regents of the University of California.  All rights reserved.
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
 *	@(#)tty.c	8.8 (Berkeley) 1/21/94
 */
/*-
 * TODO:
 *	o Fix races for sending the start char in ttyflush().
 *	o Handle inter-byte timeout for "MIN > 0, TIME > 0" in ttyselect().
 *	  With luck, there will be MIN chars before select() returns().
 *	o Handle CLOCAL consistently for ptys.  Perhaps disallow setting it.
 *	o Don't allow input in TS_ZOMBIE case.  It would be visible through
 *	  FIONREAD.
 *	o Do the new sio locking stuff here and use it to avoid special
 *	  case for EXTPROC?
 *	o Lock PENDIN too?
 *	o Move EXTPROC and/or PENDIN to t_state?
 *	o Wrap most of ttioctl in spltty/splx.
 *	o Implement TIOCNOTTY or remove it from <sys/ioctl.h>.
 *	o Send STOP if IXOFF is toggled off while TS_TBLOCK is set.
 *	o Don't allow certain termios flags to affect disciplines other
 *	  than TTYDISC.  Cancel their effects before switch disciplines
 *	  and ignore them if they are set while we are in another
 *	  discipline.
 *	o Handle c_ispeed = 0 to c_ispeed = c_ospeed conversion here instead
 *	  of in drivers and fix drivers that write to tp->t_termios.
 *	o Check for TS_CARR_ON being set while everything is closed and not
 *	  waiting for carrier.  TS_CARR_ON isn't cleared if nothing is open,
 *	  so it would live until the next open even if carrier drops.
 *	o Restore TS_WOPEN since it is useful in pstat.  It must be cleared
 *	  only when _all_ openers leave open().
 */
#ifdef NeXT
#define NSNP		0
#else
#include "snp.h"
#include "opt_uconsole.h"
#endif

#include <sys/param.h>
#define	TTYDEFCHARS 1
#include <sys/systm.h>
#undef	TTYDEFCHARS
#include <sys/ioctl.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/file_internal.h>
#include <sys/conf.h>
#include <sys/dkstat.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/syslog.h>
#include <sys/user.h>
#include <sys/signalvar.h>
#include <sys/signalvar.h>
#ifndef NeXT
#include <sys/resourcevar.h>
#endif
#include <sys/malloc.h>
#if NSNP > 0
#include <sys/snoop.h>
#endif

#ifndef NeXT
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_prot.h>
#include <vm/lock.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#else
#include <dev/kmreg_com.h>
#include <machine/cons.h>
#include <machine/spl.h>
#if 0 /* [ */
#include <machdep/machine/pmap.h>
#endif  /* 0 ] */
#endif /* !NeXT */
#include <sys/resource.h>	/* averunnable */

#ifndef NeXT
static int	proc_compare(struct proc *p1, struct proc *p2);
#endif /* NeXT */
static int	ttnread(struct tty *tp);
static void	ttyecho(int c, struct tty *tp);
static int	ttyoutput(int c, register struct tty *tp);
static void	ttypend(struct tty *tp);
static void	ttyretype(struct tty *tp);
static void	ttyrub(int c, struct tty *tp);
static void	ttyrubo(struct tty *tp, int count);
static void	ttystop(struct tty *tp, int rw);
static void	ttyunblock(struct tty *tp);
static int	ttywflush(struct tty *tp);
static int	proc_compare(struct proc *p1, struct proc *p2);

/*
 * Table with character classes and parity. The 8th bit indicates parity,
 * the 7th bit indicates the character is an alphameric or underscore (for
 * ALTWERASE), and the low 6 bits indicate delay type.  If the low 6 bits
 * are 0 then the character needs no special processing on output; classes
 * other than 0 might be translated or (not currently) require delays.
 */
#define	E	0x00	/* Even parity. */
#define	O	0x80	/* Odd parity. */
#define	PARITY(c)	(char_type[c] & O)

#define	ALPHA	0x40	/* Alpha or underscore. */
#define	ISALPHA(c)	(char_type[(c) & TTY_CHARMASK] & ALPHA)

#define	CCLASSMASK	0x3f
#define	CCLASS(c)	(char_type[c] & CCLASSMASK)

#define	BS	BACKSPACE
#define	CC	CONTROL
#define	CR	RETURN
#define	NA	ORDINARY | ALPHA
#define	NL	NEWLINE
#define	NO	ORDINARY
#define	TB	TAB
#define	VT	VTAB

static u_char const char_type[] = {
	E|CC, O|CC, O|CC, E|CC, O|CC, E|CC, E|CC, O|CC,	/* nul - bel */
	O|BS, E|TB, E|NL, O|CC, E|VT, O|CR, O|CC, E|CC, /* bs - si */
	O|CC, E|CC, E|CC, O|CC, E|CC, O|CC, O|CC, E|CC, /* dle - etb */
	E|CC, O|CC, O|CC, E|CC, O|CC, E|CC, E|CC, O|CC, /* can - us */
	O|NO, E|NO, E|NO, O|NO, E|NO, O|NO, O|NO, E|NO, /* sp - ' */
	E|NO, O|NO, O|NO, E|NO, O|NO, E|NO, E|NO, O|NO, /* ( - / */
	E|NA, O|NA, O|NA, E|NA, O|NA, E|NA, E|NA, O|NA, /* 0 - 7 */
	O|NA, E|NA, E|NO, O|NO, E|NO, O|NO, O|NO, E|NO, /* 8 - ? */
	O|NO, E|NA, E|NA, O|NA, E|NA, O|NA, O|NA, E|NA, /* @ - G */
	E|NA, O|NA, O|NA, E|NA, O|NA, E|NA, E|NA, O|NA, /* H - O */
	E|NA, O|NA, O|NA, E|NA, O|NA, E|NA, E|NA, O|NA, /* P - W */
	O|NA, E|NA, E|NA, O|NO, E|NO, O|NO, O|NO, O|NA, /* X - _ */
	E|NO, O|NA, O|NA, E|NA, O|NA, E|NA, E|NA, O|NA, /* ` - g */
	O|NA, E|NA, E|NA, O|NA, E|NA, O|NA, O|NA, E|NA, /* h - o */
	O|NA, E|NA, E|NA, O|NA, E|NA, O|NA, O|NA, E|NA, /* p - w */
	E|NA, O|NA, O|NA, E|NO, O|NO, E|NO, E|NO, O|CC, /* x - del */
	/*
	 * Meta chars; should be settable per character set;
	 * for now, treat them all as normal characters.
	 */
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
	NA,   NA,   NA,   NA,   NA,   NA,   NA,   NA,
};
#undef	BS
#undef	CC
#undef	CR
#undef	NA
#undef	NL
#undef	NO
#undef	TB
#undef	VT

/* Macros to clear/set/test flags. */
#define	SET(t, f)	(t) |= (f)
#define	CLR(t, f)	(t) &= ~(f)
#define	ISSET(t, f)	((t) & (f))

/*
 * Input control starts when we would not be able to fit the maximum
 * contents of the ping-pong buffers and finishes when we would be able
 * to fit that much plus 1/8 more.
 */
#define	I_HIGH_WATER	(TTYHOG - 2 * 256)	/* XXX */
#define	I_LOW_WATER	((TTYHOG - 2 * 256) * 7 / 8)	/* XXX */

#undef MAX_INPUT		/* XXX wrong in <sys/syslimits.h> */
#define	MAX_INPUT	TTYHOG

static void
termios32to64(struct termios *in, struct user_termios *out)
{
	out->c_iflag = (user_tcflag_t)in->c_iflag;
	out->c_oflag = (user_tcflag_t)in->c_oflag;
	out->c_cflag = (user_tcflag_t)in->c_cflag;
	out->c_lflag = (user_tcflag_t)in->c_lflag;

	/* bcopy is OK, since this type is ILP32/LP64 size invariant */
	bcopy(in->c_cc, out->c_cc, sizeof(in->c_cc));

	out->c_ispeed = (user_speed_t)in->c_ispeed;
	out->c_ospeed = (user_speed_t)in->c_ospeed;
}

static void
termios64to32(struct user_termios *in, struct termios *out)
{
	out->c_iflag = (tcflag_t)in->c_iflag;
	out->c_oflag = (tcflag_t)in->c_oflag;
	out->c_cflag = (tcflag_t)in->c_cflag;
	out->c_lflag = (tcflag_t)in->c_lflag;

	/* bcopy is OK, since this type is ILP32/LP64 size invariant */
	bcopy(in->c_cc, out->c_cc, sizeof(in->c_cc));

	out->c_ispeed = (speed_t)in->c_ispeed;
	out->c_ospeed = (speed_t)in->c_ospeed;
}


/*
 * Initial open of tty, or (re)entry to standard tty line discipline.
 */
int
ttyopen(device, tp)
	dev_t device;
	register struct tty *tp;
{
	int s;
	boolean_t funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	s = spltty();
	tp->t_dev = device;
	if (!ISSET(tp->t_state, TS_ISOPEN)) {
		SET(tp->t_state, TS_ISOPEN);
		if (ISSET(tp->t_cflag, CLOCAL)) {
			SET(tp->t_state, TS_CONNECTED); }
		bzero(&tp->t_winsize, sizeof(tp->t_winsize));
	}

#ifndef NeXT
	/*
	 * Initialize or restore a cblock allocation policy suitable for
	 * the standard line discipline.
	 */
	clist_alloc_cblocks(&tp->t_canq, TTYHOG, 512);
	clist_alloc_cblocks(&tp->t_outq, TTMAXHIWAT + OBUFSIZ + 100,
			    TTMAXHIWAT + OBUFSIZ + 100);
	clist_alloc_cblocks(&tp->t_rawq, TTYHOG, TTYHOG);
#endif /* !NeXT */

	splx(s);
	thread_funnel_set(kernel_flock, funnel_state);
	return (0);
}

/*
 * Handle close() on a tty line: flush and set to initial state,
 * bumping generation number so that pending read/write calls
 * can detect recycling of the tty.
 * XXX our caller should have done `spltty(); l_close(); ttyclose();'
 * and l_close() should have flushed, but we repeat the spltty() and
 * the flush in case there are buggy callers.
 */
int
ttyclose(tp)
	register struct tty *tp;
{
	int s;

	s = spltty();
	if (constty == tp) {
		constty = NULL;

splx(s);
spltty();

#ifdef NeXT
		/*
		 * Closing current console tty; disable printing of console
		 * messages at bottom-level driver. 
		 */
		(*cdevsw[major(tp->t_dev)].d_ioctl)
			(tp->t_dev, KMIOCDISABLCONS, NULL, 0, current_proc());
#endif	/* NeXT */
	}

	ttyflush(tp, FREAD | FWRITE);
#ifndef NeXT
	clist_free_cblocks(&tp->t_canq);
	clist_free_cblocks(&tp->t_outq);
	clist_free_cblocks(&tp->t_rawq);
#endif

#if NSNP > 0
	if (ISSET(tp->t_state, TS_SNOOP) && tp->t_sc != NULL)
		snpdown((struct snoop *)tp->t_sc);
#endif

	tp->t_gen++;
	tp->t_line = TTYDISC;
	tp->t_pgrp = NULL;
	tp->t_session = NULL;
	tp->t_state = 0;
#if NeXT
	selthreadclear(&tp->t_wsel);
	selthreadclear(&tp->t_rsel);
#endif
	splx(s);
	return (0);
}

#define	FLUSHQ(q) {							\
	if ((q)->c_cc)							\
		ndflush(q, (q)->c_cc);					\
}

/* Is 'c' a line delimiter ("break" character)? */
#define	TTBREAKC(c, lflag)							\
	((c) == '\n' || (((c) == cc[VEOF] ||				\
	  (c) == cc[VEOL] || ((c) == cc[VEOL2] && lflag & IEXTEN)) &&	\
	 (c) != _POSIX_VDISABLE))

/*
 * Process input of a single character received on a tty.
 */
int
ttyinput(c, tp)
	register int c;
	register struct tty *tp;
{
	register tcflag_t iflag, lflag;
	register cc_t *cc;
	int i, err, retval;
	boolean_t funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
        
	/*
	 * If input is pending take it first.
	 */
	lflag = tp->t_lflag;
	if (ISSET(lflag, PENDIN))
		ttypend(tp);
	/*
	 * Gather stats.
	 */
	if (ISSET(lflag, ICANON)) {
		++tk_cancc;
		++tp->t_cancc;
	} else {
		++tk_rawcc;
		++tp->t_rawcc;
	}
	++tk_nin;

	/*
	 * Block further input iff:
	 * current input > threshold AND input is available to user program
	 * AND input flow control is enabled and not yet invoked.
	 * The 3 is slop for PARMRK.
	 */
	iflag = tp->t_iflag;
	if (tp->t_rawq.c_cc + tp->t_canq.c_cc > I_HIGH_WATER - 3 &&
	    (!ISSET(lflag, ICANON) || tp->t_canq.c_cc != 0) &&
	    (ISSET(tp->t_cflag, CRTS_IFLOW) || ISSET(iflag, IXOFF)) &&
	    !ISSET(tp->t_state, TS_TBLOCK))
		ttyblock(tp);

	/* Handle exceptional conditions (break, parity, framing). */
	cc = tp->t_cc;
	err = (ISSET(c, TTY_ERRORMASK));
	if (err) {
		CLR(c, TTY_ERRORMASK);
		if (ISSET(err, TTY_BI)) {
			if (ISSET(iflag, IGNBRK)) {
				thread_funnel_set(kernel_flock, funnel_state);
				return (0);
                        }
			if (ISSET(iflag, BRKINT)) {
				ttyflush(tp, FREAD | FWRITE);
				pgsignal(tp->t_pgrp, SIGINT, 1);
				goto endcase;
			}
			if (ISSET(iflag, PARMRK))
				goto parmrk;
		} else if ((ISSET(err, TTY_PE) && ISSET(iflag, INPCK))
			|| ISSET(err, TTY_FE)) {
			if (ISSET(iflag, IGNPAR)) {
				thread_funnel_set(kernel_flock, funnel_state);
				return (0);
			}
			else if (ISSET(iflag, PARMRK)) {
parmrk:
				if (tp->t_rawq.c_cc + tp->t_canq.c_cc >
				    MAX_INPUT - 3)
					goto input_overflow;
				(void)putc(0377 | TTY_QUOTE, &tp->t_rawq);
				(void)putc(0 | TTY_QUOTE, &tp->t_rawq);
				(void)putc(c | TTY_QUOTE, &tp->t_rawq);
				goto endcase;
			} else
				c = 0;
		}
	}

	if (!ISSET(tp->t_state, TS_TYPEN) && ISSET(iflag, ISTRIP))
		CLR(c, 0x80);
	if (!ISSET(lflag, EXTPROC)) {
		/*
		 * Check for literal nexting very first
		 */
		if (ISSET(tp->t_state, TS_LNCH)) {
			SET(c, TTY_QUOTE);
			CLR(tp->t_state, TS_LNCH);
		}
		/*
		 * Scan for special characters.  This code
		 * is really just a big case statement with
		 * non-constant cases.  The bottom of the
		 * case statement is labeled ``endcase'', so goto
		 * it after a case match, or similar.
		 */

		/*
		 * Control chars which aren't controlled
		 * by ICANON, ISIG, or IXON.
		 */
		if (ISSET(lflag, IEXTEN)) {
			if (CCEQ(cc[VLNEXT], c)) {
				if (ISSET(lflag, ECHO)) {
					if (ISSET(lflag, ECHOE)) {
						(void)ttyoutput('^', tp);
						(void)ttyoutput('\b', tp);
					} else
						ttyecho(c, tp);
				}
				SET(tp->t_state, TS_LNCH);
				goto endcase;
			}
			if (CCEQ(cc[VDISCARD], c)) {
				if (ISSET(lflag, FLUSHO))
					CLR(tp->t_lflag, FLUSHO);
				else {
					ttyflush(tp, FWRITE);
					ttyecho(c, tp);
					if (tp->t_rawq.c_cc + tp->t_canq.c_cc)
						ttyretype(tp);
					SET(tp->t_lflag, FLUSHO);
				}
				goto startoutput;
			}
		}
		/*
		 * Signals.
		 */
		if (ISSET(lflag, ISIG)) {
			if (CCEQ(cc[VINTR], c) || CCEQ(cc[VQUIT], c)) {
				if (!ISSET(lflag, NOFLSH))
					ttyflush(tp, FREAD | FWRITE);
				ttyecho(c, tp);
				pgsignal(tp->t_pgrp,
				    CCEQ(cc[VINTR], c) ? SIGINT : SIGQUIT, 1);
				goto endcase;
			}
			if (CCEQ(cc[VSUSP], c)) {
				if (!ISSET(lflag, NOFLSH))
					ttyflush(tp, FREAD);
				ttyecho(c, tp);
				pgsignal(tp->t_pgrp, SIGTSTP, 1);
				goto endcase;
			}
		}
		/*
		 * Handle start/stop characters.
		 */
		if (ISSET(iflag, IXON)) {
			if (CCEQ(cc[VSTOP], c)) {
				if (!ISSET(tp->t_state, TS_TTSTOP)) {
					SET(tp->t_state, TS_TTSTOP);
                                        ttystop(tp, 0);
					thread_funnel_set(kernel_flock, funnel_state);
					return (0);
				}
				if (!CCEQ(cc[VSTART], c)) {
					thread_funnel_set(kernel_flock, funnel_state);
					return (0);
                                }
				/*
				 * if VSTART == VSTOP then toggle
				 */
				goto endcase;
			}
			if (CCEQ(cc[VSTART], c))
				goto restartoutput;
		}
		/*
		 * IGNCR, ICRNL, & INLCR
		 */
		if (c == '\r') {
			if (ISSET(iflag, IGNCR)) {
				thread_funnel_set(kernel_flock, funnel_state);
				return (0);
                        }
			else if (ISSET(iflag, ICRNL))
				c = '\n';
		} else if (c == '\n' && ISSET(iflag, INLCR))
			c = '\r';
	}
	if (!ISSET(tp->t_lflag, EXTPROC) && ISSET(lflag, ICANON)) {
		/*
		 * From here on down canonical mode character
		 * processing takes place.
		 */
		/*
		 * erase (^H / ^?)
		 */
		if (CCEQ(cc[VERASE], c)) {
			if (tp->t_rawq.c_cc)
				ttyrub(unputc(&tp->t_rawq), tp);
			goto endcase;
		}
		/*
		 * kill (^U)
		 */
		if (CCEQ(cc[VKILL], c)) {
			if (ISSET(lflag, ECHOKE) &&
			    tp->t_rawq.c_cc == tp->t_rocount &&
			    !ISSET(lflag, ECHOPRT))
				while (tp->t_rawq.c_cc)
					ttyrub(unputc(&tp->t_rawq), tp);
			else {
				ttyecho(c, tp);
				if (ISSET(lflag, ECHOK) ||
				    ISSET(lflag, ECHOKE))
					ttyecho('\n', tp);
				FLUSHQ(&tp->t_rawq);
				tp->t_rocount = 0;
			}
			CLR(tp->t_state, TS_LOCAL);
			goto endcase;
		}
		/*
		 * word erase (^W)
		 */
		if (CCEQ(cc[VWERASE], c) && ISSET(lflag, IEXTEN)) {
			int ctype;

			/*
			 * erase whitespace
			 */
			while ((c = unputc(&tp->t_rawq)) == ' ' || c == '\t')
				ttyrub(c, tp);
			if (c == -1)
				goto endcase;
			/*
			 * erase last char of word and remember the
			 * next chars type (for ALTWERASE)
			 */
			ttyrub(c, tp);
			c = unputc(&tp->t_rawq);
			if (c == -1)
				goto endcase;
			if (c == ' ' || c == '\t') {
				(void)putc(c, &tp->t_rawq);
				goto endcase;
			}
			ctype = ISALPHA(c);
			/*
			 * erase rest of word
			 */
			do {
				ttyrub(c, tp);
				c = unputc(&tp->t_rawq);
				if (c == -1)
					goto endcase;
			} while (c != ' ' && c != '\t' &&
			    (!ISSET(lflag, ALTWERASE) || ISALPHA(c) == ctype));
			(void)putc(c, &tp->t_rawq);
			goto endcase;
		}
		/*
		 * reprint line (^R)
		 */
		if (CCEQ(cc[VREPRINT], c) && ISSET(lflag, IEXTEN)) {
			ttyretype(tp);
			goto endcase;
		}
		/*
		 * ^T - kernel info and generate SIGINFO
		 */
		if (CCEQ(cc[VSTATUS], c) && ISSET(lflag, IEXTEN)) {
			if (ISSET(lflag, ISIG))
				pgsignal(tp->t_pgrp, SIGINFO, 1);
			if (!ISSET(lflag, NOKERNINFO))
				ttyinfo(tp);
			goto endcase;
		}
	}
	/*
	 * Check for input buffer overflow
	 */
	if (tp->t_rawq.c_cc + tp->t_canq.c_cc >= MAX_INPUT) {
input_overflow:
		if (ISSET(iflag, IMAXBEL)) {
			if (tp->t_outq.c_cc < tp->t_hiwat)
				(void)ttyoutput(CTRL('g'), tp);
		}
		goto endcase;
	}

	if (   c == 0377 && ISSET(iflag, PARMRK) && !ISSET(iflag, ISTRIP)
	     && ISSET(iflag, IGNBRK|IGNPAR) != (IGNBRK|IGNPAR))
		(void)putc(0377 | TTY_QUOTE, &tp->t_rawq);

	/*
	 * Put data char in q for user and
	 * wakeup on seeing a line delimiter.
	 */
	if (putc(c, &tp->t_rawq) >= 0) {
		if (!ISSET(lflag, ICANON)) {
			ttwakeup(tp);
			ttyecho(c, tp);
			goto endcase;
		}
		if (TTBREAKC(c, lflag)) {
			tp->t_rocount = 0;
			catq(&tp->t_rawq, &tp->t_canq);
			ttwakeup(tp);
		} else if (tp->t_rocount++ == 0)
			tp->t_rocol = tp->t_column;
		if (ISSET(tp->t_state, TS_ERASE)) {
			/*
			 * end of prterase \.../
			 */
			CLR(tp->t_state, TS_ERASE);
			(void)ttyoutput('/', tp);
		}
		i = tp->t_column;
		ttyecho(c, tp);
		if (CCEQ(cc[VEOF], c) && ISSET(lflag, ECHO)) {
			/*
			 * Place the cursor over the '^' of the ^D.
			 */
			i = min(2, tp->t_column - i);
			while (i > 0) {
				(void)ttyoutput('\b', tp);
				i--;
			}
		}
	}
endcase:
	/*
	 * IXANY means allow any character to restart output.
	 */
	if (ISSET(tp->t_state, TS_TTSTOP) &&
	    !ISSET(iflag, IXANY) && cc[VSTART] != cc[VSTOP]) {
		thread_funnel_set(kernel_flock, funnel_state);
		return (0);
        }
restartoutput:
	CLR(tp->t_lflag, FLUSHO);
	CLR(tp->t_state, TS_TTSTOP);
startoutput:
    retval = ttstart(tp);
	thread_funnel_set(kernel_flock, funnel_state);
	return (retval);
}

/*
 * Output a single character on a tty, doing output processing
 * as needed (expanding tabs, newline processing, etc.).
 * Returns < 0 if succeeds, otherwise returns char to resend.
 * Must be recursive.
 */
static int
ttyoutput(c, tp)
	register int c;
	register struct tty *tp;
{
	register tcflag_t oflag;
	register int col, s;

	oflag = tp->t_oflag;
	if (!ISSET(oflag, OPOST)) {
		if (ISSET(tp->t_lflag, FLUSHO))
			return (-1);
		if (putc(c, &tp->t_outq))
			return (c);
		tk_nout++;
		tp->t_outcc++;
		return (-1);
	}
	/*
	 * Do tab expansion if OXTABS is set.  Special case if we external
	 * processing, we don't do the tab expansion because we'll probably
	 * get it wrong.  If tab expansion needs to be done, let it happen
	 * externally.
	 */
	CLR(c, ~TTY_CHARMASK);
	if (c == '\t' &&
	    ISSET(oflag, OXTABS) && !ISSET(tp->t_lflag, EXTPROC)) {
		c = 8 - (tp->t_column & 7);
		if (!ISSET(tp->t_lflag, FLUSHO)) {
			s = spltty();		/* Don't interrupt tabs. */
			c -= b_to_q("        ", c, &tp->t_outq);
			tk_nout += c;
			tp->t_outcc += c;
			splx(s);
		}
		tp->t_column += c;
		return (c ? -1 : '\t');
	}
	if (c == CEOT && ISSET(oflag, ONOEOT))
		return (-1);

	/*
	 * Newline translation: if ONLCR is set,
	 * translate newline into "\r\n".
	 */
	if (c == '\n' && ISSET(tp->t_oflag, ONLCR)) {
		tk_nout++;
		tp->t_outcc++;
		if (putc('\r', &tp->t_outq))
			return (c);
	}
	tk_nout++;
	tp->t_outcc++;
	if (!ISSET(tp->t_lflag, FLUSHO) && putc(c, &tp->t_outq))
		return (c);

	col = tp->t_column;
	switch (CCLASS(c)) {
	case BACKSPACE:
		if (col > 0)
			--col;
		break;
	case CONTROL:
		break;
	case NEWLINE:
	case RETURN:
		col = 0;
		break;
	case ORDINARY:
		++col;
		break;
	case TAB:
		col = (col + 8) & ~7;
		break;
	}
	tp->t_column = col;
	return (-1);
}

/*
 * Ioctls for all tty devices.  Called after line-discipline specific ioctl
 * has been called to do discipline-specific functions and/or reject any
 * of these ioctl commands.
 */
/* ARGSUSED */
int
ttioctl(register struct tty *tp,
	u_long cmd, caddr_t data, int flag,
	struct proc *p)
{
	int s, error;
	struct uthread *ut;

	ut = (struct uthread *)get_bsdthread_info(current_thread());
	/* If the ioctl involves modification, hang if in the background. */
	switch (cmd) {
	case  TIOCFLUSH:
	case  TIOCSETA:
	case  TIOCSETA_64:
	case  TIOCSETD:
	case  TIOCSETAF:
	case  TIOCSETAF_64:
	case  TIOCSETAW:
	case  TIOCSETAW_64:
#ifdef notdef
	case  TIOCSPGRP:
#endif
	case  TIOCSTAT:
	case  TIOCSTI:
	case  TIOCSWINSZ:
#if COMPAT_43_TTY || defined(COMPAT_SUNOS)
	case  TIOCLBIC:
	case  TIOCLBIS:
	case  TIOCLSET:
	case  TIOCSETC:
	case OTIOCSETD:
	case  TIOCSETN:
	case  TIOCSETP:
	case  TIOCSLTC:
#endif
		while (isbackground(p, tp) &&
		    (p->p_flag & P_PPWAIT) == 0 &&
		    (p->p_sigignore & sigmask(SIGTTOU)) == 0 &&
		    (ut->uu_sigmask & sigmask(SIGTTOU)) == 0) {
			if (p->p_pgrp->pg_jobc == 0)
				return (EIO);
			pgsignal(p->p_pgrp, SIGTTOU, 1);
			error = ttysleep(tp, &lbolt, TTOPRI | PCATCH | PTTYBLOCK, "ttybg1",
					 0);
			if (error)
				return (error);
		}
		break;
	}

	switch (cmd) {			/* Process the ioctl. */
	case FIOASYNC:			/* set/clear async i/o */
		s = spltty();
		if (*(int *)data)
			SET(tp->t_state, TS_ASYNC);
		else
			CLR(tp->t_state, TS_ASYNC);
		splx(s);
		break;
	case FIONBIO:			/* set/clear non-blocking i/o */
		break;			/* XXX: delete. */
	case FIONREAD:			/* get # bytes to read */
		s = spltty();
		*(int *)data = ttnread(tp);
		splx(s);
		break;
	case TIOCEXCL:			/* set exclusive use of tty */
		s = spltty();
		SET(tp->t_state, TS_XCLUDE);
		splx(s);
		break;
	case TIOCFLUSH: {		/* flush buffers */
		register int flags = *(int *)data;

		if (flags == 0)
			flags = FREAD | FWRITE;
		else
			flags &= FREAD | FWRITE;
		ttyflush(tp, flags);
		break;
	}
#ifdef	NeXT
	case TIOCSCONS: {
		/* Set current console device to this line */
		int bogusData = 1;
		data = (caddr_t) &bogusData;

		/* No break - Fall through to BSD code */
	}
#endif /* NeXT */
	case TIOCCONS: {			/* become virtual console */
		if (*(int *)data) {
			if (constty && constty != tp &&
			    ISSET(constty->t_state, TS_CONNECTED)) {
				return (EBUSY);
			}
#if defined(NeXT) || !defined(UCONSOLE)
			if ( (error = suser(kauth_cred_get(), &p->p_acflag)) )
				return (error);
#endif
			constty = tp;
		} else if (tp == constty) {
			constty = NULL;
		}
#ifdef	NeXT
		if (constty) {
			(*cdevsw[major(cons.t_dev)].d_ioctl)
				(cons.t_dev, KMIOCDISABLCONS, NULL, 0, p);
		} else {
			(*cdevsw[major(tp->t_dev)].d_ioctl)
				(tp->t_dev, KMIOCDISABLCONS, NULL, 0, p);
		}
#endif /* NeXT */
		break;
	}
	case TIOCDRAIN:			/* wait till output drained */
		error = ttywait(tp);
		if (error)
			return (error);
		break;
	case TIOCGETA:		/* get termios struct */
	case TIOCGETA_64: {		/* get termios struct */
		if (IS_64BIT_PROCESS(p)) {
			termios32to64(&tp->t_termios, (struct user_termios *)data);
		} else {
			bcopy(&tp->t_termios, data, sizeof(struct termios));
		}
		break;
	}
	case TIOCGETD:			/* get line discipline */
		*(int *)data = tp->t_line;
		break;
	case TIOCGWINSZ:		/* get window size */
		*(struct winsize *)data = tp->t_winsize;
		break;
	case TIOCGPGRP:			/* get pgrp of tty */
		if (!isctty(p, tp))
			return (ENOTTY);
		*(int *)data = tp->t_pgrp ? tp->t_pgrp->pg_id : NO_PID;
		break;
#ifdef TIOCHPCL
	case TIOCHPCL:			/* hang up on last close */
		s = spltty();
		SET(tp->t_cflag, HUPCL);
		splx(s);
		break;
#endif
	case TIOCNXCL:			/* reset exclusive use of tty */
		s = spltty();
		CLR(tp->t_state, TS_XCLUDE);
		splx(s);
		break;
	case TIOCOUTQ:			/* output queue size */
		*(int *)data = tp->t_outq.c_cc;
		break;
	case TIOCSETA:			/* set termios struct */
	case TIOCSETA_64:
	case TIOCSETAW:			/* drain output, set */
	case TIOCSETAW_64:
	case TIOCSETAF:		/* drn out, fls in, set */
	case TIOCSETAF_64: {		/* drn out, fls in, set */
		register struct termios *t = (struct termios *)data;
		struct termios lcl_termios;

		if (IS_64BIT_PROCESS(p)) {
			termios64to32((struct user_termios *)data, &lcl_termios);
			t = &lcl_termios;
		}
		if (t->c_ispeed < 0 || t->c_ospeed < 0)
			return (EINVAL);
		s = spltty();
		if (cmd == TIOCSETAW || cmd == TIOCSETAF ||
		    cmd == TIOCSETAW_64 || cmd == TIOCSETAF_64) {
			error = ttywait(tp);
			if (error) {
				splx(s);
				return (error);
			}
			if (cmd == TIOCSETAF || cmd == TIOCSETAF_64)
				ttyflush(tp, FREAD);
		}
		if (!ISSET(t->c_cflag, CIGNORE)) {
			/*
			 * Set device hardware.
			 */
			if (tp->t_param && (error = (*tp->t_param)(tp, t))) {
				splx(s);
				return (error);
			}
			if (ISSET(t->c_cflag, CLOCAL) &&
			    !ISSET(tp->t_cflag, CLOCAL)) {
				/*
				 * XXX disconnections would be too hard to
				 * get rid of without this kludge.  The only
				 * way to get rid of controlling terminals
				 * is to exit from the session leader.
				 */
				CLR(tp->t_state, TS_ZOMBIE);

				wakeup(TSA_CARR_ON(tp));
				ttwakeup(tp);
				ttwwakeup(tp);
			}
			if ((ISSET(tp->t_state, TS_CARR_ON) ||
			     ISSET(t->c_cflag, CLOCAL)) &&
			    !ISSET(tp->t_state, TS_ZOMBIE))
				SET(tp->t_state, TS_CONNECTED);
			else
				CLR(tp->t_state, TS_CONNECTED);
			tp->t_cflag = t->c_cflag;
			tp->t_ispeed = t->c_ispeed;
			tp->t_ospeed = t->c_ospeed;
			ttsetwater(tp);
		}
		if (ISSET(t->c_lflag, ICANON) != ISSET(tp->t_lflag, ICANON) &&
		    cmd != TIOCSETAF && cmd != TIOCSETAF_64) {
			if (ISSET(t->c_lflag, ICANON))
				SET(tp->t_lflag, PENDIN);
			else {
				/*
				 * XXX we really shouldn't allow toggling
				 * ICANON while we're in a non-termios line
				 * discipline.  Now we have to worry about
				 * panicing for a null queue.
				 */
#ifndef NeXT
				if (tp->t_canq.c_cbreserved > 0 &&
				    tp->t_rawq.c_cbreserved > 0) {
					catq(&tp->t_rawq, &tp->t_canq);
					/*
					 * XXX the queue limits may be
					 * different, so the old queue
					 * swapping method no longer works.
					 */
					catq(&tp->t_canq, &tp->t_rawq);
				}
#else
				if (tp->t_rawq.c_cs && tp->t_canq.c_cs) {
				    struct clist tq;

				    catq(&tp->t_rawq, &tp->t_canq);
				    tq = tp->t_rawq;
				    tp->t_rawq = tp->t_canq;
				    tp->t_canq = tq;
				}
#endif /* !NeXT */
				CLR(tp->t_lflag, PENDIN);
			}
			ttwakeup(tp);
		}
		tp->t_iflag = t->c_iflag;
		tp->t_oflag = t->c_oflag;
		/*
		 * Make the EXTPROC bit read only.
		 */
		if (ISSET(tp->t_lflag, EXTPROC))
			SET(t->c_lflag, EXTPROC);
		else
			CLR(t->c_lflag, EXTPROC);
		tp->t_lflag = t->c_lflag | ISSET(tp->t_lflag, PENDIN);
		if (t->c_cc[VMIN] != tp->t_cc[VMIN] ||
		    t->c_cc[VTIME] != tp->t_cc[VTIME])
			ttwakeup(tp);
		bcopy(t->c_cc, tp->t_cc, sizeof(t->c_cc));
		splx(s);
		break;
	}
	case TIOCSETD: {		/* set line discipline */
		register int t = *(int *)data;
		dev_t device = tp->t_dev;

		if (t >= nlinesw)
			return (ENXIO);
		if (t != tp->t_line) {
			s = spltty();
			(*linesw[tp->t_line].l_close)(tp, flag);
			error = (*linesw[t].l_open)(device, tp);
			if (error) {
				(void)(*linesw[tp->t_line].l_open)(device, tp);
				splx(s);
				return (error);
			}
			tp->t_line = t;
			splx(s);
		}
		break;
	}
	case TIOCSTART:			/* start output, like ^Q */
		s = spltty();
		if (ISSET(tp->t_state, TS_TTSTOP) ||
		    ISSET(tp->t_lflag, FLUSHO)) {
			CLR(tp->t_lflag, FLUSHO);
			CLR(tp->t_state, TS_TTSTOP);
			ttstart(tp);
		}
		splx(s);
		break;
	case TIOCSTI:			/* simulate terminal input */
		if (suser(kauth_cred_get(), NULL) && (flag & FREAD) == 0)
			return (EPERM);
		if (suser(kauth_cred_get(), NULL) && !isctty(p, tp))
			return (EACCES);
		s = spltty();
		(*linesw[tp->t_line].l_rint)(*(u_char *)data, tp);
		splx(s);
		break;
	case TIOCSTOP:			/* stop output, like ^S */
		s = spltty();
		if (!ISSET(tp->t_state, TS_TTSTOP)) {
			SET(tp->t_state, TS_TTSTOP);
                        ttystop(tp, 0);
		}
		splx(s);
		break;
	case TIOCSCTTY:			/* become controlling tty */
		/* Session ctty vnode pointer set in vnode layer. */
		if (!SESS_LEADER(p) ||
		    ((p->p_session->s_ttyvp || tp->t_session) &&
		    (tp->t_session != p->p_session)))
			return (EPERM);
		tp->t_session = p->p_session;
		tp->t_pgrp = p->p_pgrp;
		p->p_session->s_ttyp = tp;
		p->p_flag |= P_CONTROLT;
		/* The backgrounded process blocking on tty now 
		 * could be foregound process. Wake such processes
		 */
		tty_pgsignal(tp->t_pgrp, SIGCONT);
		break;
	case TIOCSPGRP: {		/* set pgrp of tty */
		register struct pgrp *pgrp = pgfind(*(int *)data);

		if (!isctty(p, tp))
			return (ENOTTY);
		else if (pgrp == NULL || pgrp->pg_session != p->p_session)
			return (EPERM);
		tp->t_pgrp = pgrp;
		/* The backgrounded process blocking on tty now 
		 * could be foregound process. Wake such processes
		 */
		tty_pgsignal(tp->t_pgrp, SIGCONT);
		break;
	}
	case TIOCSTAT:			/* simulate control-T */
		s = spltty();
		ttyinfo(tp);
		splx(s);
		break;
	case TIOCSWINSZ:		/* set window size */
		if (bcmp((caddr_t)&tp->t_winsize, data,
		    sizeof (struct winsize))) {
			tp->t_winsize = *(struct winsize *)data;
			pgsignal(tp->t_pgrp, SIGWINCH, 1);
		}
		break;
	case TIOCSDRAINWAIT:
		error = suser(kauth_cred_get(), &p->p_acflag);
		if (error)
			return (error);
		tp->t_timeout = *(int *)data * hz;
		wakeup(TSA_OCOMPLETE(tp));
		wakeup(TSA_OLOWAT(tp));
		break;
	case TIOCGDRAINWAIT:
		*(int *)data = tp->t_timeout / hz;
		break;
	default:
#if COMPAT_43_TTY || defined(COMPAT_SUNOS)
#ifdef NeXT
		return (ttcompat(tp, cmd, data, flag, p));
#else
		return (ttcompat(tp, cmd, data, flag));
#endif /* NeXT */
#else
		return (ENOTTY);
#endif
	}

	return (0);
}

int
ttyselect(tp, rw, wql, p)
	struct tty *tp;
	int rw;
	void * wql;
	struct proc *p;
{
	int s;

	if (tp == NULL)
		return (ENXIO);

	s = spltty();
	switch (rw) {
	case FREAD:
		if (ttnread(tp) > 0 || ISSET(tp->t_state, TS_ZOMBIE))
			goto win;
		selrecord(p, &tp->t_rsel, wql);
		break;
	case FWRITE:
		if ((tp->t_outq.c_cc <= tp->t_lowat &&
		     ISSET(tp->t_state, TS_CONNECTED))
		    || ISSET(tp->t_state, TS_ZOMBIE)) {
win:			splx(s);
			return (1);
		}
		selrecord(p, &tp->t_wsel, wql);
		break;
	}
	splx(s);
	return (0);
}

/*
 * This is a wrapper for compatibility with the select vector used by
 * cdevsw.  It relies on a proper xxxdevtotty routine.
 */
int
ttselect(dev, rw, wql, p)
	dev_t dev;
	int rw;
	void * wql;
	struct proc *p;
{
#ifndef NeXT
	return ttyselect((*cdevsw[major(dev)]->d_devtotty)(dev), rw, wql, p);
#else
	return ttyselect(cdevsw[major(dev)].d_ttys[minor(dev)], rw, wql, p);
#endif
}

/*
 * Must be called at spltty().
 */
static int
ttnread(tp)
	struct tty *tp;
{
	int nread;

	if (ISSET(tp->t_lflag, PENDIN))
		ttypend(tp);
	nread = tp->t_canq.c_cc;
	if (!ISSET(tp->t_lflag, ICANON)) {
		nread += tp->t_rawq.c_cc;
		if (nread < tp->t_cc[VMIN] && tp->t_cc[VTIME] == 0)
			nread = 0;
	}
	return (nread);
}

/*
 * Wait for output to drain.
 */
int
ttywait(tp)
	register struct tty *tp;
{
	int error, s;

	error = 0;
	s = spltty();
	while ((tp->t_outq.c_cc || ISSET(tp->t_state, TS_BUSY)) &&
	       ISSET(tp->t_state, TS_CONNECTED) && tp->t_oproc) {
		(*tp->t_oproc)(tp);
		if ((tp->t_outq.c_cc || ISSET(tp->t_state, TS_BUSY)) &&
		    ISSET(tp->t_state, TS_CONNECTED)) {
			SET(tp->t_state, TS_SO_OCOMPLETE);
			error = ttysleep(tp, TSA_OCOMPLETE(tp),
					 TTOPRI | PCATCH, "ttywai",
					 tp->t_timeout);
			if (error) {
				if (error == EWOULDBLOCK)
					error = EIO;
				break;
			}
		} else
			break;
	}
	if (!error && (tp->t_outq.c_cc || ISSET(tp->t_state, TS_BUSY)))
		error = EIO;
	splx(s);
	return (error);
}

static void
ttystop(tp, rw)
        struct tty *tp;
        int rw;
{
#ifdef sun4c						/* XXX */
	(*tp->t_stop)(tp, rw);
#elif defined(NeXT)
	(*cdevsw[major(tp->t_dev)].d_stop)(tp, rw);
#else
	(*cdevsw[major(tp->t_dev)]->d_stop)(tp, rw);
#endif
}

/*
 * Flush if successfully wait.
 */
static int
ttywflush(tp)
	struct tty *tp;
{
	int error;

	if ((error = ttywait(tp)) == 0)
		ttyflush(tp, FREAD);
	return (error);
}

/*
 * Flush tty read and/or write queues, notifying anyone waiting.
 */
void
ttyflush(tp, rw)
	register struct tty *tp;
	int rw;
{
	register int s;

	s = spltty();
#if 0
again:
#endif
	if (rw & FWRITE) {
		FLUSHQ(&tp->t_outq);
		CLR(tp->t_state, TS_TTSTOP);
	}
        ttystop(tp, rw);
        if (rw & FREAD) {
		FLUSHQ(&tp->t_canq);
		FLUSHQ(&tp->t_rawq);
		CLR(tp->t_lflag, PENDIN);
		tp->t_rocount = 0;
		tp->t_rocol = 0;
		CLR(tp->t_state, TS_LOCAL);
		ttwakeup(tp);
		if (ISSET(tp->t_state, TS_TBLOCK)) {
			if (rw & FWRITE)
				FLUSHQ(&tp->t_outq);
			ttyunblock(tp);

			/*
			 * Don't let leave any state that might clobber the
			 * next line discipline (although we should do more
			 * to send the START char).  Not clearing the state
			 * may have caused the "putc to a clist with no
			 * reserved cblocks" panic/printf.
			 */
			CLR(tp->t_state, TS_TBLOCK);

#if 0 /* forget it, sleeping isn't always safe and we don't know when it is */
			if (ISSET(tp->t_iflag, IXOFF)) {
				/*
				 * XXX wait a bit in the hope that the stop
				 * character (if any) will go out.  Waiting
				 * isn't good since it allows races.  This
				 * will be fixed when the stop character is
				 * put in a special queue.  Don't bother with
				 * the checks in ttywait() since the timeout
				 * will save us.
				 */
				SET(tp->t_state, TS_SO_OCOMPLETE);
				ttysleep(tp, TSA_OCOMPLETE(tp), TTOPRI,
					 "ttyfls", hz / 10);
				/*
				 * Don't try sending the stop character again.
				 */
				CLR(tp->t_state, TS_TBLOCK);
				goto again;
			}
#endif
		}
	}
	if (rw & FWRITE) {
		FLUSHQ(&tp->t_outq);
		ttwwakeup(tp);
	}
	splx(s);
}

/*
 * Copy in the default termios characters.
 */
void
termioschars(t)
	struct termios *t;
{

	bcopy(ttydefchars, t->c_cc, sizeof t->c_cc);
}

/*
 * Old interface.
 */
void
ttychars(tp)
	struct tty *tp;
{

	termioschars(&tp->t_termios);
}

/*
 * Handle input high water.  Send stop character for the IXOFF case.  Turn
 * on our input flow control bit and propagate the changes to the driver.
 * XXX the stop character should be put in a special high priority queue.
 */
void
ttyblock(tp)
	struct tty *tp;
{

	SET(tp->t_state, TS_TBLOCK);
	if (ISSET(tp->t_iflag, IXOFF) && tp->t_cc[VSTOP] != _POSIX_VDISABLE &&
	    putc(tp->t_cc[VSTOP], &tp->t_outq) != 0)
		CLR(tp->t_state, TS_TBLOCK);	/* try again later */
	ttstart(tp);
}

/*
 * Handle input low water.  Send start character for the IXOFF case.  Turn
 * off our input flow control bit and propagate the changes to the driver.
 * XXX the start character should be put in a special high priority queue.
 */
static void
ttyunblock(tp)
	struct tty *tp;
{

	CLR(tp->t_state, TS_TBLOCK);
	if (ISSET(tp->t_iflag, IXOFF) && tp->t_cc[VSTART] != _POSIX_VDISABLE &&
	    putc(tp->t_cc[VSTART], &tp->t_outq) != 0)
		SET(tp->t_state, TS_TBLOCK);	/* try again later */
	ttstart(tp);
}

#if defined(NeXT) || defined(notyet)
/* FreeBSD: Not used by any current (i386) drivers. */
/*
 * Restart after an inter-char delay.
 */
void
ttrstrt(tp_arg)
	void *tp_arg;
{
	struct tty *tp;
	int s;

#if DIAGNOSTIC
	if (tp_arg == NULL)
		panic("ttrstrt");
#endif
	tp = tp_arg;
	s = spltty();

	CLR(tp->t_state, TS_TIMEOUT);
	ttstart(tp);

	splx(s);
}
#endif /* NeXT || notyet */

int
ttstart(tp)
	struct tty *tp;
{
	boolean_t funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	if (tp->t_oproc != NULL)	/* XXX: Kludge for pty. */
		(*tp->t_oproc)(tp);
	thread_funnel_set(kernel_flock, funnel_state);
	return (0);
}

/*
 * "close" a line discipline
 */
int
ttylclose(tp, flag)
	struct tty *tp;
	int flag;
{
	boolean_t funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	if ( (flag & FNONBLOCK) || ttywflush(tp))
		ttyflush(tp, FREAD | FWRITE);
	thread_funnel_set(kernel_flock, funnel_state);
	return (0);
}

/*
 * Handle modem control transition on a tty.
 * Flag indicates new state of carrier.
 * Returns 0 if the line should be turned off, otherwise 1.
 */
int
ttymodem(tp, flag)
	register struct tty *tp;
	int flag;
{
	boolean_t funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	if (ISSET(tp->t_state, TS_CARR_ON) && ISSET(tp->t_cflag, MDMBUF)) {
		/*
		 * MDMBUF: do flow control according to carrier flag
		 * XXX TS_CAR_OFLOW doesn't do anything yet.  TS_TTSTOP
		 * works if IXON and IXANY are clear.
		 */
		if (flag) {
			CLR(tp->t_state, TS_CAR_OFLOW);
			CLR(tp->t_state, TS_TTSTOP);
			ttstart(tp);
		} else if (!ISSET(tp->t_state, TS_CAR_OFLOW)) {
			SET(tp->t_state, TS_CAR_OFLOW);
			SET(tp->t_state, TS_TTSTOP);
                        ttystop(tp, 0);
		}
	} else if (flag == 0) {
		/*
		 * Lost carrier.
		 */
		CLR(tp->t_state, TS_CARR_ON);
		if (ISSET(tp->t_state, TS_ISOPEN) &&
		    !ISSET(tp->t_cflag, CLOCAL)) {
			SET(tp->t_state, TS_ZOMBIE);
			CLR(tp->t_state, TS_CONNECTED);
			if (tp->t_session && tp->t_session->s_leader)
				psignal(tp->t_session->s_leader, SIGHUP);
			ttyflush(tp, FREAD | FWRITE);
			thread_funnel_set(kernel_flock, funnel_state);
			return (0);
		}
	} else {
		/*
		 * Carrier now on.
		 */
		SET(tp->t_state, TS_CARR_ON);
		if (!ISSET(tp->t_state, TS_ZOMBIE))
			SET(tp->t_state, TS_CONNECTED);
		wakeup(TSA_CARR_ON(tp));
		ttwakeup(tp);
		ttwwakeup(tp);
	}
	thread_funnel_set(kernel_flock, funnel_state);
	return (1);
}

/*
 * Reinput pending characters after state switch
 * call at spltty().
 */
static void
ttypend(tp)
	register struct tty *tp;
{
	struct clist tq;
	register int c;

	CLR(tp->t_lflag, PENDIN);
	SET(tp->t_state, TS_TYPEN);
#ifndef NeXT
	/*
	 * XXX this assumes too much about clist internals.  It may even
	 * fail if the cblock slush pool is empty.  We can't allocate more
	 * cblocks here because we are called from an interrupt handler
	 * and clist_alloc_cblocks() can wait.
	 */
	tq = tp->t_rawq;
	bzero(&tp->t_rawq, sizeof tp->t_rawq);
	tp->t_rawq.c_cbmax = tq.c_cbmax;
	tp->t_rawq.c_cbreserved = tq.c_cbreserved;
#else
	tq = tp->t_rawq;
	tp->t_rawq.c_cc = 0;
	tp->t_rawq.c_cf = tp->t_rawq.c_cl = 0;
#endif /* !NeXT */
	while ((c = getc(&tq)) >= 0)
		ttyinput(c, tp);
	CLR(tp->t_state, TS_TYPEN);
}

/*
 * Process a read call on a tty device.
 */
int
ttread(tp, uio, flag)
	register struct tty *tp;
	struct uio *uio;
	int flag;
{
	register struct clist *qp;
	register int c;
	register tcflag_t lflag;
	register cc_t *cc = tp->t_cc;
	register struct proc *p = current_proc();
	int s, first, error = 0;
	int has_etime = 0, last_cc = 0;
	long slp = 0;		/* XXX this should be renamed `timo'. */
	boolean_t funnel_state;
	struct uthread *ut;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	ut = (struct uthread *)get_bsdthread_info(current_thread());

loop:
	s = spltty();
	lflag = tp->t_lflag;
	/*
	 * take pending input first
	 */
	if (ISSET(lflag, PENDIN)) {
		ttypend(tp);
		splx(s);	/* reduce latency */
		s = spltty();
		lflag = tp->t_lflag;	/* XXX ttypend() clobbers it */
	}

	/*
	 * Hang process if it's in the background.
	 */
	if (isbackground(p, tp)) {
		splx(s);
		if ((p->p_sigignore & sigmask(SIGTTIN)) ||
		   (ut->uu_sigmask & sigmask(SIGTTIN)) ||
		    p->p_flag & P_PPWAIT || p->p_pgrp->pg_jobc == 0) {
			thread_funnel_set(kernel_flock, funnel_state);
			return (EIO);
		}
		pgsignal(p->p_pgrp, SIGTTIN, 1);
		error = ttysleep(tp, &lbolt, TTIPRI | PCATCH | PTTYBLOCK, "ttybg2", 0);
		if (error){
			thread_funnel_set(kernel_flock, funnel_state);
			return (error);
		}
		goto loop;
	}

	if (ISSET(tp->t_state, TS_ZOMBIE)) {
		splx(s);
		thread_funnel_set(kernel_flock, funnel_state);
		return (0);	/* EOF */
	}

	/*
	 * If canonical, use the canonical queue,
	 * else use the raw queue.
	 *
	 * (should get rid of clists...)
	 */
	qp = ISSET(lflag, ICANON) ? &tp->t_canq : &tp->t_rawq;

	if (flag & IO_NDELAY) {
		if (qp->c_cc > 0)
			goto read;
		if (!ISSET(lflag, ICANON) && cc[VMIN] == 0) {
			splx(s);
			thread_funnel_set(kernel_flock, funnel_state);
			return (0);
		}
		splx(s);
		thread_funnel_set(kernel_flock, funnel_state);
		return (EWOULDBLOCK);
	}
	if (!ISSET(lflag, ICANON)) {
		int m = cc[VMIN];
		long t = cc[VTIME];
		struct timeval etime, timecopy;

		/*
		 * Check each of the four combinations.
		 * (m > 0 && t == 0) is the normal read case.
		 * It should be fairly efficient, so we check that and its
		 * companion case (m == 0 && t == 0) first.
		 * For the other two cases, we compute the target sleep time
		 * into slp.
		 */
		if (t == 0) {
			if (qp->c_cc < m)
				goto sleep;
			if (qp->c_cc > 0)
				goto read;

			/* m, t and qp->c_cc are all 0.  0 is enough input. */
			splx(s);
			thread_funnel_set(kernel_flock, funnel_state);
			return (0);
		}
		t *= 100000;		/* time in us */
#define diff(t1, t2) (((t1).tv_sec - (t2).tv_sec) * 1000000 + \
			 ((t1).tv_usec - (t2).tv_usec))
		if (m > 0) {
			if (qp->c_cc <= 0)
				goto sleep;
			if (qp->c_cc >= m)
				goto read;
			microuptime(&timecopy);
			if (!has_etime) {
				/* first character, start timer */
				has_etime = 1;

				etime.tv_sec = t / 1000000;
				etime.tv_usec = (t - (etime.tv_sec * 1000000));
				timeradd(&etime, &timecopy, &etime);
				
				slp = t;
			} else if (qp->c_cc > last_cc) {
				/* got a character, restart timer */

				etime.tv_sec = t / 1000000;
				etime.tv_usec = (t - (etime.tv_sec * 1000000));
				timeradd(&etime, &timecopy, &etime);

				slp = t;
			} else {
				/* nothing, check expiration */
			        if (timercmp(&etime, &timecopy, <=))
					goto read;

				slp = diff(etime, timecopy);
			}
			last_cc = qp->c_cc;
		} else {	/* m == 0 */
			if (qp->c_cc > 0)
				goto read;
			microuptime(&timecopy);
			if (!has_etime) {
				has_etime = 1;

				etime.tv_sec = t / 1000000;
				etime.tv_usec = (t - (etime.tv_sec * 1000000));
				timeradd(&etime, &timecopy, &etime);

				slp = t;
			} else {
			        if (timercmp(&etime, &timecopy, <=)) {
					/* Timed out, but 0 is enough input. */
					splx(s);
					thread_funnel_set(kernel_flock, funnel_state);
					return (0);
				}
				slp = diff(etime, timecopy);
			}
		}
#undef diff
		/*
		 * Rounding down may make us wake up just short
		 * of the target, so we round up.
		 * The formula is ceiling(slp * hz/1000000).
		 * 32-bit arithmetic is enough for hz < 169.
		 * XXX see hzto() for how to avoid overflow if hz
		 * is large (divide by `tick' and/or arrange to
		 * use hzto() if hz is large).
		 */
		slp = (long) (((u_long)slp * hz) + 999999) / 1000000;
		goto sleep;
	}
	if (qp->c_cc <= 0) {
sleep:
		/*
		 * There is no input, or not enough input and we can block.
		 */
		error = ttysleep(tp, TSA_HUP_OR_INPUT(tp), TTIPRI | PCATCH,
				 ISSET(tp->t_state, TS_CONNECTED) ?
				 "ttyin" : "ttyhup", (int)slp);
		splx(s);
		if (error == EWOULDBLOCK)
			error = 0;
		else if (error) {
			thread_funnel_set(kernel_flock, funnel_state);
			return (error);
		}
		/*
		 * XXX what happens if another process eats some input
		 * while we are asleep (not just here)?  It would be
		 * safest to detect changes and reset our state variables
		 * (has_stime and last_cc).
		 */
		slp = 0;
		goto loop;
	}
read:
	splx(s);
	/*
	 * Input present, check for input mapping and processing.
	 */
	first = 1;
#ifdef NeXT
	if (ISSET(lflag, ICANON)
	|| (ISSET(lflag, IEXTEN | ISIG) == (IEXTEN | ISIG)) )
#else
	if (ISSET(lflag, ICANON | ISIG))
#endif
		goto slowcase;
	for (;;) {
		char ibuf[IBUFSIZ];
		int icc;

		icc = min(uio_resid(uio), IBUFSIZ);
		icc = q_to_b(qp, ibuf, icc);
		if (icc <= 0) {
			if (first)
				goto loop;
			break;
		}
		error = uiomove(ibuf, icc, uio);
		/*
		 * XXX if there was an error then we should ungetc() the
		 * unmoved chars and reduce icc here.
		 */
#if NSNP > 0
		if (ISSET(tp->t_lflag, ECHO) &&
		    ISSET(tp->t_state, TS_SNOOP) && tp->t_sc != NULL)
			snpin((struct snoop *)tp->t_sc, ibuf, icc);
#endif
		if (error)
			break;
 		if (uio_resid(uio) == 0)
			break;
		first = 0;
	}
	goto out;
slowcase:
	for (;;) {
		c = getc(qp);
		if (c < 0) {
			if (first)
				goto loop;
			break;
		}
		/*
		 * delayed suspend (^Y)
		 */
		if (CCEQ(cc[VDSUSP], c) &&
		    ISSET(lflag, IEXTEN | ISIG) == (IEXTEN | ISIG)) {
			pgsignal(tp->t_pgrp, SIGTSTP, 1);
			if (first) {
				error = ttysleep(tp, &lbolt, TTIPRI | PCATCH,
						 "ttybg3", 0);
				if (error)
					break;
				goto loop;
			}
			break;
		}
		/*
		 * Interpret EOF only in canonical mode.
		 */
		if (CCEQ(cc[VEOF], c) && ISSET(lflag, ICANON))
			break;
		/*
		 * Give user character.
		 */
 		error = ureadc(c, uio);
		if (error)
			/* XXX should ungetc(c, qp). */
			break;
#if NSNP > 0
		/*
		 * Only snoop directly on input in echo mode.  Non-echoed
		 * input will be snooped later iff the application echoes it.
		 */
		if (ISSET(tp->t_lflag, ECHO) &&
		    ISSET(tp->t_state, TS_SNOOP) && tp->t_sc != NULL)
			snpinc((struct snoop *)tp->t_sc, (char)c);
#endif
 		if (uio_resid(uio) == 0)
			break;
		/*
		 * In canonical mode check for a "break character"
		 * marking the end of a "line of input".
		 */
		if (ISSET(lflag, ICANON) && TTBREAKC(c, lflag))
			break;
		first = 0;
	}

out:
	/*
	 * Look to unblock input now that (presumably)
	 * the input queue has gone down.
	 */
	s = spltty();
	if (ISSET(tp->t_state, TS_TBLOCK) &&
	    tp->t_rawq.c_cc + tp->t_canq.c_cc <= I_LOW_WATER)
		ttyunblock(tp);
	splx(s);

	thread_funnel_set(kernel_flock, funnel_state);
	return (error);
}

/*
 * Check the output queue on tp for space for a kernel message (from uprintf
 * or tprintf).  Allow some space over the normal hiwater mark so we don't
 * lose messages due to normal flow control, but don't let the tty run amok.
 * Sleeps here are not interruptible, but we return prematurely if new signals
 * arrive.
 */
int
ttycheckoutq(tp, wait)
	register struct tty *tp;
	int wait;
{
	int hiwat, s;
	sigset_t oldsig;
	struct uthread *ut;

	ut = (struct uthread *)get_bsdthread_info(current_thread());

	hiwat = tp->t_hiwat;
	s = spltty();
	oldsig = wait ? ut->uu_siglist : 0;
	if (tp->t_outq.c_cc > hiwat + OBUFSIZ + 100)
		while (tp->t_outq.c_cc > hiwat) {
			ttstart(tp);
			if (tp->t_outq.c_cc <= hiwat)
				break;
			if (wait == 0 || ut->uu_siglist != oldsig) {
				splx(s);
				return (0);
			}
			SET(tp->t_state, TS_SO_OLOWAT);
			tsleep(TSA_OLOWAT(tp), PZERO - 1, "ttoutq", hz);
		}
	splx(s);
	return (1);
}

/*
 * Process a write call on a tty device.
 */
int
ttwrite(tp, uio, flag)
	register struct tty *tp;
	register struct uio *uio;
	int flag;
{
	register char *cp = NULL;
	register int cc, ce;
	register struct proc *p;
	int i, hiwat, count, error, s;
	char obuf[OBUFSIZ];
	boolean_t funnel_state;
	struct uthread *ut;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	ut = (struct uthread *)get_bsdthread_info(current_thread());
	hiwat = tp->t_hiwat;
	// LP64todo - fix this!
	count = uio_resid(uio);
	error = 0;
	cc = 0;
loop:
	s = spltty();
	if (ISSET(tp->t_state, TS_ZOMBIE)) {
		splx(s);
		if (uio_resid(uio) == count)
			error = EIO;
		goto out;
	}
	if (!ISSET(tp->t_state, TS_CONNECTED)) {
		if (flag & IO_NDELAY) {
			splx(s);
			error = EWOULDBLOCK;
			goto out;
		}
		error = ttysleep(tp, TSA_CARR_ON(tp), TTIPRI | PCATCH,
				 "ttydcd", 0);
		splx(s);
		if (error) {
			goto out; }
		goto loop;
	}
	splx(s);
	/*
	 * Hang the process if it's in the background.
	 */
	p = current_proc();
	if (isbackground(p, tp) &&
	    ISSET(tp->t_lflag, TOSTOP) && (p->p_flag & P_PPWAIT) == 0 &&
	    (p->p_sigignore & sigmask(SIGTTOU)) == 0 &&
	    (ut->uu_sigmask & sigmask(SIGTTOU)) == 0) {
		if (p->p_pgrp->pg_jobc == 0) {
			error = EIO;
			goto out;
		}
		pgsignal(p->p_pgrp, SIGTTOU, 1);
		error = ttysleep(tp, &lbolt, TTIPRI | PCATCH | PTTYBLOCK, "ttybg4", 0);
		if (error)
			goto out;
		goto loop;
	}
	/*
	 * Process the user's data in at most OBUFSIZ chunks.  Perform any
	 * output translation.  Keep track of high water mark, sleep on
	 * overflow awaiting device aid in acquiring new space.
	 */
	while (uio_resid(uio) > 0 || cc > 0) {
		if (ISSET(tp->t_lflag, FLUSHO)) {
			uio_setresid(uio, 0);
			thread_funnel_set(kernel_flock, funnel_state);
			return (0);
		}
		if (tp->t_outq.c_cc > hiwat)
			goto ovhiwat;
		/*
		 * Grab a hunk of data from the user, unless we have some
		 * leftover from last time.
		 */
		if (cc == 0) {
			cc = min(uio_resid(uio), OBUFSIZ);
			cp = obuf;
			error = uiomove(cp, cc, uio);
			if (error) {
				cc = 0;
				break;
			}
#if NSNP > 0
			if (ISSET(tp->t_state, TS_SNOOP) && tp->t_sc != NULL)
				snpin((struct snoop *)tp->t_sc, cp, cc);
#endif
		}
		/*
		 * If nothing fancy need be done, grab those characters we
		 * can handle without any of ttyoutput's processing and
		 * just transfer them to the output q.  For those chars
		 * which require special processing (as indicated by the
		 * bits in char_type), call ttyoutput.  After processing
		 * a hunk of data, look for FLUSHO so ^O's will take effect
		 * immediately.
		 */
		while (cc > 0) {
			if (!ISSET(tp->t_oflag, OPOST))
				ce = cc;
			else {
				ce = cc - scanc((u_int)cc, (u_char *)cp,
						char_type, CCLASSMASK);
				/*
				 * If ce is zero, then we're processing
				 * a special character through ttyoutput.
				 */
				if (ce == 0) {
					tp->t_rocount = 0;
					if (ttyoutput(*cp, tp) >= 0) {
#ifdef NeXT
						/* out of space */
						goto overfull;
#else
						/* No Clists, wait a bit. */
						ttstart(tp);
						if (flag & IO_NDELAY) {
							error = EWOULDBLOCK;
							goto out;
						}
						error = ttysleep(tp, &lbolt,
								 TTOPRI|PCATCH,
								 "ttybf1", 0);
						if (error)
							goto out;
						goto loop;
#endif /* NeXT */
					}
					cp++;
					cc--;
					if (ISSET(tp->t_lflag, FLUSHO) ||
					    tp->t_outq.c_cc > hiwat)
						goto ovhiwat;
					continue;
				}
			}
			/*
			 * A bunch of normal characters have been found.
			 * Transfer them en masse to the output queue and
			 * continue processing at the top of the loop.
			 * If there are any further characters in this
			 * <= OBUFSIZ chunk, the first should be a character
			 * requiring special handling by ttyoutput.
			 */
			tp->t_rocount = 0;
			i = b_to_q(cp, ce, &tp->t_outq);
			ce -= i;
			tp->t_column += ce;
			cp += ce, cc -= ce, tk_nout += ce;
			tp->t_outcc += ce;
			if (i > 0) {
#ifdef NeXT
				/* out of space */
				goto overfull;
#else
				/* No Clists, wait a bit. */
				ttstart(tp);
				if (flag & IO_NDELAY) {
					error = EWOULDBLOCK;
					goto out;
				}
				error = ttysleep(tp, &lbolt, TTOPRI | PCATCH,
						 "ttybf2", 0);
				if (error)
					goto out;
				goto loop;
#endif /* NeXT */
			}
			if (ISSET(tp->t_lflag, FLUSHO) ||
			    tp->t_outq.c_cc > hiwat)
				break;
		}
		ttstart(tp);
	}
out:
	/*
	 * If cc is nonzero, we leave the uio structure inconsistent, as the
	 * offset and iov pointers have moved forward, but it doesn't matter
	 * (the call will either return short or restart with a new uio).
	 */
	uio_setresid(uio, (uio_resid(uio) + cc));
	thread_funnel_set(kernel_flock, funnel_state);
	return (error);

#ifdef NeXT
overfull:

	/*
	 * Since we are using ring buffers, if we can't insert any more into
	 * the output queue, we can assume the ring is full and that someone
	 * forgot to set the high water mark correctly.  We set it and then
	 * proceed as normal.
	 */
	hiwat = tp->t_outq.c_cc - 1;
#endif

ovhiwat:
	ttstart(tp);
	s = spltty();
	/*
	 * This can only occur if FLUSHO is set in t_lflag,
	 * or if ttstart/oproc is synchronous (or very fast).
	 */
	if (tp->t_outq.c_cc <= hiwat) {
		splx(s);
		goto loop;
	}
	if (flag & IO_NDELAY) {
		splx(s);
		uio_setresid(uio, (uio_resid(uio) + cc));
		thread_funnel_set(kernel_flock, funnel_state);
		return (uio_resid(uio) == count ? EWOULDBLOCK : 0);
	}
	SET(tp->t_state, TS_SO_OLOWAT);
	error = ttysleep(tp, TSA_OLOWAT(tp), TTOPRI | PCATCH, "ttywri",
			 tp->t_timeout);
	splx(s);
	if (error == EWOULDBLOCK)
		error = EIO;
	if (error)
		goto out;
	goto loop;
}

/*
 * Rubout one character from the rawq of tp
 * as cleanly as possible.
 */
static void
ttyrub(c, tp)
	register int c;
	register struct tty *tp;
{
	register u_char *cp;
	register int savecol;
	int tabc, s;

	if (!ISSET(tp->t_lflag, ECHO) || ISSET(tp->t_lflag, EXTPROC))
		return;
	CLR(tp->t_lflag, FLUSHO);
	if (ISSET(tp->t_lflag, ECHOE)) {
		if (tp->t_rocount == 0) {
			/*
			 * Messed up by ttwrite; retype
			 */
			ttyretype(tp);
			return;
		}
		if (c == ('\t' | TTY_QUOTE) || c == ('\n' | TTY_QUOTE))
			ttyrubo(tp, 2);
		else {
			CLR(c, ~TTY_CHARMASK);
			switch (CCLASS(c)) {
			case ORDINARY:
				ttyrubo(tp, 1);
				break;
			case BACKSPACE:
			case CONTROL:
			case NEWLINE:
			case RETURN:
			case VTAB:
				if (ISSET(tp->t_lflag, ECHOCTL))
					ttyrubo(tp, 2);
				break;
			case TAB:
				if (tp->t_rocount < tp->t_rawq.c_cc) {
					ttyretype(tp);
					return;
				}
				s = spltty();
				savecol = tp->t_column;
				SET(tp->t_state, TS_CNTTB);
				SET(tp->t_lflag, FLUSHO);
				tp->t_column = tp->t_rocol;
#ifndef NeXT
				cp = tp->t_rawq.c_cf;
				if (cp)
					tabc = *cp;	/* XXX FIX NEXTC */
				for (; cp; cp = nextc(&tp->t_rawq, cp, &tabc))
					ttyecho(tabc, tp);
#else
				for (cp = firstc(&tp->t_rawq, &tabc); cp;
				    cp = nextc(&tp->t_rawq, cp, &tabc))
					ttyecho(tabc, tp);
#endif /* !NeXT */
				CLR(tp->t_lflag, FLUSHO);
				CLR(tp->t_state, TS_CNTTB);
				splx(s);

				/* savecol will now be length of the tab. */
				savecol -= tp->t_column;
				tp->t_column += savecol;
				if (savecol > 8)
					savecol = 8;	/* overflow fixup */
				while (--savecol >= 0)
					(void)ttyoutput('\b', tp);
				break;
			default:			/* XXX */
#define	PANICSTR	"ttyrub: would panic c = %d, val = %d\n"
				(void)printf(PANICSTR, c, CCLASS(c));
#ifdef notdef
				panic(PANICSTR, c, CCLASS(c));
#endif
			}
		}
	} else if (ISSET(tp->t_lflag, ECHOPRT)) {
		if (!ISSET(tp->t_state, TS_ERASE)) {
			SET(tp->t_state, TS_ERASE);
			(void)ttyoutput('\\', tp);
		}
		ttyecho(c, tp);
	} else
		ttyecho(tp->t_cc[VERASE], tp);
	--tp->t_rocount;
}

/*
 * Back over count characters, erasing them.
 */
static void
ttyrubo(struct tty *tp, int count)
{

	while (count-- > 0) {
		(void)ttyoutput('\b', tp);
		(void)ttyoutput(' ', tp);
		(void)ttyoutput('\b', tp);
	}
}

/*
 * ttyretype --
 *	Reprint the rawq line.  Note, it is assumed that c_cc has already
 *	been checked.
 */
static void
ttyretype(tp)
	register struct tty *tp;
{
	register u_char *cp;
	int s, c;

	/* Echo the reprint character. */
	if (tp->t_cc[VREPRINT] != _POSIX_VDISABLE)
		ttyecho(tp->t_cc[VREPRINT], tp);

	(void)ttyoutput('\n', tp);

	/*
	 * FREEBSD XXX
	 * FIX: NEXTC IS BROKEN - DOESN'T CHECK QUOTE
	 * BIT OF FIRST CHAR.
	 */
	s = spltty();
#ifndef NeXT
	for (cp = tp->t_canq.c_cf, c = (cp != NULL ? *cp : 0);
	    cp != NULL; cp = nextc(&tp->t_canq, cp, &c))
		ttyecho(c, tp);
	for (cp = tp->t_rawq.c_cf, c = (cp != NULL ? *cp : 0);
	    cp != NULL; cp = nextc(&tp->t_rawq, cp, &c))
		ttyecho(c, tp);
#else NeXT
	for (cp = firstc(&tp->t_canq, &c); cp; cp = nextc(&tp->t_canq, cp, &c))
		ttyecho(c, tp);
	for (cp = firstc(&tp->t_rawq, &c); cp; cp = nextc(&tp->t_rawq, cp, &c))
		ttyecho(c, tp);
#endif /* !NeXT */
	CLR(tp->t_state, TS_ERASE);
	splx(s);

	tp->t_rocount = tp->t_rawq.c_cc;
	tp->t_rocol = 0;
}

/*
 * Echo a typed character to the terminal.
 */
static void
ttyecho(c, tp)
	register int c;
	register struct tty *tp;
{

	if (!ISSET(tp->t_state, TS_CNTTB))
		CLR(tp->t_lflag, FLUSHO);
	if ((!ISSET(tp->t_lflag, ECHO) &&
	     (c != '\n' || !ISSET(tp->t_lflag, ECHONL))) ||
	    ISSET(tp->t_lflag, EXTPROC))
		return;
	if (ISSET(tp->t_lflag, ECHOCTL) &&
	    ((ISSET(c, TTY_CHARMASK) <= 037 && c != '\t' && c != '\n') ||
	    ISSET(c, TTY_CHARMASK) == 0177)) {
		(void)ttyoutput('^', tp);
		CLR(c, ~TTY_CHARMASK);
		if (c == 0177)
			c = '?';
		else
			c += 'A' - 1;
	}
	(void)ttyoutput(c, tp);
}

/*
 * Wake up any readers on a tty.
 */
void
ttwakeup(tp)
	register struct tty *tp;
{

#ifndef NeXT
	if (tp->t_rsel.si_pid != 0)
#endif
		selwakeup(&tp->t_rsel);
	if (ISSET(tp->t_state, TS_ASYNC))
		pgsignal(tp->t_pgrp, SIGIO, 1);
	wakeup(TSA_HUP_OR_INPUT(tp));
}

/*
 * Wake up any writers on a tty.
 */
void
ttwwakeup(tp)
	register struct tty *tp;
{
#ifndef NeXT
	if (tp->t_wsel.si_pid != 0 && tp->t_outq.c_cc <= tp->t_lowat)
#else
	if (tp->t_outq.c_cc <= tp->t_lowat)
#endif
		selwakeup(&tp->t_wsel);
	if (ISSET(tp->t_state, TS_BUSY | TS_SO_OCOMPLETE) ==
	    TS_SO_OCOMPLETE && tp->t_outq.c_cc == 0) {
		CLR(tp->t_state, TS_SO_OCOMPLETE);
		wakeup(TSA_OCOMPLETE(tp));
	}
	if (ISSET(tp->t_state, TS_SO_OLOWAT) &&
	    tp->t_outq.c_cc <= tp->t_lowat) {
		CLR(tp->t_state, TS_SO_OLOWAT);
		wakeup(TSA_OLOWAT(tp));
	}
}

/*
 * Look up a code for a specified speed in a conversion table;
 * used by drivers to map software speed values to hardware parameters.
 */
int
ttspeedtab(speed, table)
	int speed;
	register struct speedtab *table;
{

	for ( ; table->sp_speed != -1; table++)
		if (table->sp_speed == speed)
			return (table->sp_code);
	return (-1);
}

/*
 * Set tty hi and low water marks.
 *
 * Try to arrange the dynamics so there's about one second
 * from hi to low water.
 *
 */
void
ttsetwater(struct tty *tp)
{
	int cps;
	unsigned int x;

#define CLAMP(x, h, l)	((x) > h ? h : ((x) < l) ? l : (x))

	cps = tp->t_ospeed / 10;
	tp->t_lowat = x = CLAMP(cps / 2, TTMAXLOWAT, TTMINLOWAT);
	x += cps;
	x = CLAMP(x, TTMAXHIWAT, TTMINHIWAT);
	tp->t_hiwat = roundup(x, CBSIZE);
#undef	CLAMP
}

/* NeXT ttyinfo has been converted to the MACH kernel */
#include <mach/thread_info.h>

/* XXX Should be in Mach header <kern/thread.h>, but doesn't work */
extern kern_return_t	thread_info_internal(thread_t thread,
				thread_flavor_t flavor,
				thread_info_t thread_info_out,
				mach_msg_type_number_t *thread_info_count);

/*
 * Report on state of foreground process group.
 */
void
ttyinfo(struct tty *tp)
{
	int		load;
	thread_t	thread;
	uthread_t	uthread;
	struct proc	*p;
	struct proc	*pick;
	const char	*state;
	struct timeval	utime;
	struct timeval	stime;
	thread_basic_info_data_t	basic_info;
	mach_msg_type_number_t		mmtn = THREAD_BASIC_INFO_COUNT;

	if (ttycheckoutq(tp,0) == 0)
		return;

	/* Print load average. */
	load = (averunnable.ldavg[0] * 100 + FSCALE / 2) >> FSHIFT;
	ttyprintf(tp, "load: %d.%02d ", load / 100, load % 100);

	/*
	 * On return following a ttyprintf(), we set tp->t_rocount to 0 so
	 * that pending input will be retyped on BS.
	 */
	if (tp->t_session == NULL) {
		ttyprintf(tp, "not a controlling terminal\n");
		tp->t_rocount = 0;
		return;
}
	if (tp->t_pgrp == NULL) {
		ttyprintf(tp, "no foreground process group\n");
		tp->t_rocount = 0;
		return;
	}
	/* first process in process group */
	if ((p = tp->t_pgrp->pg_members.lh_first) == NULL) {
		ttyprintf(tp, "empty foreground process group\n");
		tp->t_rocount = 0;
		return;
	}

	/*
	 * Pick the most interesting process and copy some of its
	 * state for printing later.
	 */
	for (pick = NULL; p != NULL; p = p->p_pglist.le_next) {
		if (proc_compare(pick, p))
			pick = p;
	}

	if (TAILQ_EMPTY(&pick->p_uthlist) ||
	    (uthread = TAILQ_FIRST(&pick->p_uthlist)) == NULL ||
	    (thread = uthread->uu_act) == NULL ||
	    (thread_info_internal(thread, THREAD_BASIC_INFO, (thread_info_t)&basic_info, &mmtn) != KERN_SUCCESS)) {
		ttyprintf(tp, "foreground process without thread\n");
		tp->t_rocount = 0;
		return;
	}

	switch(basic_info.run_state) {
	case TH_STATE_RUNNING:
		state = "running";
		break;
	case TH_STATE_STOPPED:
		state = "stopped";
		break;
	case TH_STATE_WAITING:
		state = "waiting";
		break;
	case TH_STATE_UNINTERRUPTIBLE:
		state = "uninterruptible";
		break;
	case TH_STATE_HALTED:
		state = "halted";
		break;
	default:
		state = "unknown";
		break;
	}
	calcru(pick, &utime, &stime, NULL);

	/* Print command, pid, state, utime, and stime */
	ttyprintf(tp, " cmd: %s %d %s %ld.%02ldu %ld.%02lds\n",
		pick->p_comm,
		pick->p_pid,
		state,
		(long)utime.tv_sec, utime.tv_usec / 10000,
		(long)stime.tv_sec, stime.tv_usec / 10000);
	tp->t_rocount = 0;
}

/*
 * Returns 1 if p2 is "better" than p1
 *
 * The algorithm for picking the "interesting" process is thus:
 *
 *	1) Only foreground processes are eligible - implied.
 *	2) Runnable processes are favored over anything else.  The runner
 *	   with the highest cpu utilization is picked (p_estcpu).  Ties are
 *	   broken by picking the highest pid.
 *	3) The sleeper with the shortest sleep time is next.
 *	4) Further ties are broken by picking the highest pid.
 */
#define ISRUN(p)	(((p)->p_stat == SRUN) || ((p)->p_stat == SIDL))
#define TESTAB(a, b)    ((a)<<1 | (b))
#define ONLYA   2
#define ONLYB   1
#define BOTH    3

static int
proc_compare(p1, p2)
	register struct proc *p1, *p2;
{

	if (p1 == NULL)
		return (1);
	/*
	 * see if at least one of them is runnable
	 */
	switch (TESTAB(ISRUN(p1), ISRUN(p2))) {
	case ONLYA:
		return (0);
	case ONLYB:
		return (1);
	case BOTH:
		/*
		 * tie - favor one with highest recent cpu utilization
		 */
		if (p2->p_estcpu > p1->p_estcpu)
			return (1);
		if (p1->p_estcpu > p2->p_estcpu)
			return (0);
		return (p2->p_pid > p1->p_pid);	/* tie - return highest pid */
	}
	/*
 	 * weed out zombies
	 */
	switch (TESTAB(p1->p_stat == SZOMB, p2->p_stat == SZOMB)) {
	case ONLYA:
		return (1);
	case ONLYB:
		return (0);
	case BOTH:
		return (p2->p_pid > p1->p_pid); /* tie - return highest pid */
	}
	/*
	 * pick the one with the smallest sleep time
	 */
	if (p2->p_slptime > p1->p_slptime)
		return (0);
	if (p1->p_slptime > p2->p_slptime)
		return (1);
	return (p2->p_pid > p1->p_pid);		/* tie - return highest pid */
}

/*
 * Output char to tty; console putchar style.
 */
int
tputchar(c, tp)
	int c;
	struct tty *tp;
{
	register int s;

	s = spltty();
	if (!ISSET(tp->t_state, TS_CONNECTED)) {
		splx(s);
		return (-1);
	}
	if (c == '\n')
		(void)ttyoutput('\r', tp);
	(void)ttyoutput(c, tp);
	ttstart(tp);
	splx(s);
	return (0);
}

/*
 * Sleep on chan, returning ERESTART if tty changed while we napped and
 * returning any errors (e.g. EINTR/EWOULDBLOCK) reported by tsleep.  If
 * the tty is revoked, restarting a pending call will redo validation done
 * at the start of the call.
 */
int
ttysleep(struct tty *tp, void *chan, int pri, const char *wmesg, int timo)
{
	int error;
	int gen;

	gen = tp->t_gen;
	error = tsleep(chan, pri, wmesg, timo);
	if (error)
		return (error);
	return (tp->t_gen == gen ? 0 : ERESTART);
}

#ifdef NeXT
/*
 * Allocate a tty structure and its associated buffers.
 */
struct tty *
ttymalloc(void)
{
	struct tty *tp;

	MALLOC(tp, struct tty *, sizeof(struct tty), M_TTYS, M_WAITOK|M_ZERO);
	if (tp != NULL) {
		/* XXX: default to TTYCLSIZE(1024) chars for now */
		clalloc(&tp->t_rawq, TTYCLSIZE, 1);
		clalloc(&tp->t_canq, TTYCLSIZE, 1);
		/* output queue doesn't need quoting */
		clalloc(&tp->t_outq, TTYCLSIZE, 0);
	}
	return(tp);
}

/*
 * Free a tty structure and its buffers.
 */
void
ttyfree(tp)
struct tty *tp;
{
	clfree(&tp->t_rawq);
	clfree(&tp->t_canq);
	clfree(&tp->t_outq);
	FREE(tp, M_TTYS);
}

#else /* !NeXT */

#ifdef notyet
/*
 * XXX this is usable not useful or used.  Most tty drivers have
 * ifdefs for using ttymalloc() but assume a different interface.
 */
/*
 * Allocate a tty struct.  Clists in the struct will be allocated by
 * ttyopen().
 */
struct tty *
ttymalloc()
{
        struct tty *tp;

        MALLOC(tp, struct tty *, sizeof *tp, M_TTYS, M_WAITOK|M_ZERO);
        return (tp);
}
#endif

#if 0 /* XXX not yet usable: session leader holds a ref (see kern_exit.c). */
/*
 * Free a tty struct.  Clists in the struct should have been freed by
 * ttyclose().
 */
void
ttyfree(tp)
	struct tty *tp;
{
        FREE(tp, M_TTYS);
}
#endif /* 0 */
#endif /* NeXT */
