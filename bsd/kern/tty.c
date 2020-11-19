/*
 * Copyright (c) 1997-2019 Apple Inc. All rights reserved.
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
#include <sys/param.h>
#define TTYDEFCHARS 1
#include <sys/systm.h>
#undef  TTYDEFCHARS
#include <sys/ioctl.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/file_internal.h>
#include <sys/conf.h>
#include <sys/dkstat.h>
#include <sys/uio_internal.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/syslog.h>
#include <sys/user.h>
#include <sys/signalvar.h>
#include <sys/signalvar.h>
#include <sys/malloc.h>

#include <dev/kmreg_com.h>
#include <machine/cons.h>
#include <sys/resource.h>       /* averunnable */
#include <kern/waitq.h>
#include <libkern/section_keywords.h>

static lck_grp_t        *tty_lck_grp;
static lck_grp_attr_t   *tty_lck_grp_attr;
static lck_attr_t      *tty_lck_attr;

__private_extern__ int ttnread(struct tty *tp);
static void     ttyecho(int c, struct tty *tp);
static int      ttyoutput(int c, struct tty *tp);
static void     ttypend(struct tty *tp);
static void     ttyretype(struct tty *tp);
static void     ttyrub(int c, struct tty *tp);
static void     ttyrubo(struct tty *tp, int count);
static void     ttystop(struct tty *tp, int rw);
static void     ttyunblock(struct tty *tp);
static int      ttywflush(struct tty *tp);
static int      proc_compare(proc_t p1, proc_t p2);

void ttyhold(struct tty *tp);
static void     ttydeallocate(struct tty *tp);

static int isctty(proc_t p, struct tty  *tp);
static int isctty_sp(proc_t p, struct tty  *tp, struct session *sessp);

__private_extern__ void termios32to64(struct termios32 *in, struct user_termios *out);
__private_extern__ void termios64to32(struct user_termios *in, struct termios32 *out);

/*
 * Table with character classes and parity. The 8th bit indicates parity,
 * the 7th bit indicates the character is an alphameric or underscore (for
 * ALTWERASE), and the low 6 bits indicate delay type.  If the low 6 bits
 * are 0 then the character needs no special processing on output; classes
 * other than 0 might be translated or (not currently) require delays.
 */
#define E       0x00    /* Even parity. */
#define O       0x80    /* Odd parity. */
#define PARITY(c)       (char_type[c] & O)

#define ALPHA   0x40    /* Alpha or underscore. */
#define ISALPHA(c)      (char_type[(c) & TTY_CHARMASK] & ALPHA)

#define CCLASSMASK      0x3f
#define CCLASS(c)       (char_type[c] & CCLASSMASK)
/* 0b10xxxxxx is the mask for UTF-8 continuations */
#define CCONT(c)        ((c & 0xc0) == 0x80)

#define BS      BACKSPACE
#define CC      CONTROL
#define CR      RETURN
#define NA      ORDINARY | ALPHA
#define NL      NEWLINE
#define NO      ORDINARY
#define TB      TAB
#define VT      VTAB

static u_char const char_type[] = {
	E | CC, O | CC, O | CC, E | CC, O | CC, E | CC, E | CC, O | CC, /* nul - bel */
	O | BS, E | TB, E | NL, O | CC, E | VT, O | CR, O | CC, E | CC, /* bs - si */
	O | CC, E | CC, E | CC, O | CC, E | CC, O | CC, O | CC, E | CC, /* dle - etb */
	E | CC, O | CC, O | CC, E | CC, O | CC, E | CC, E | CC, O | CC, /* can - us */
	O | NO, E | NO, E | NO, O | NO, E | NO, O | NO, O | NO, E | NO, /* sp - ' */
	E | NO, O | NO, O | NO, E | NO, O | NO, E | NO, E | NO, O | NO, /* ( - / */
	E | NA, O | NA, O | NA, E | NA, O | NA, E | NA, E | NA, O | NA, /* 0 - 7 */
	O | NA, E | NA, E | NO, O | NO, E | NO, O | NO, O | NO, E | NO, /* 8 - ? */
	O | NO, E | NA, E | NA, O | NA, E | NA, O | NA, O | NA, E | NA, /* @ - G */
	E | NA, O | NA, O | NA, E | NA, O | NA, E | NA, E | NA, O | NA, /* H - O */
	E | NA, O | NA, O | NA, E | NA, O | NA, E | NA, E | NA, O | NA, /* P - W */
	O | NA, E | NA, E | NA, O | NO, E | NO, O | NO, O | NO, O | NA, /* X - _ */
	E | NO, O | NA, O | NA, E | NA, O | NA, E | NA, E | NA, O | NA, /* ` - g */
	O | NA, E | NA, E | NA, O | NA, E | NA, O | NA, O | NA, E | NA, /* h - o */
	O | NA, E | NA, E | NA, O | NA, E | NA, O | NA, O | NA, E | NA, /* p - w */
	E | NA, O | NA, O | NA, E | NO, O | NO, E | NO, E | NO, O | CC, /* x - del */
	/*
	 * Meta chars; should be settable per character set;
	 * for now, treat them all as normal characters.
	 */
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
};
#undef  BS
#undef  CC
#undef  CR
#undef  NA
#undef  NL
#undef  NO
#undef  TB
#undef  VT

/* Macros to clear/set/test flags. */
#define SET(t, f)       (t) |= (f)
#define CLR(t, f)       (t) &= ~(f)
#define ISSET(t, f)     ((t) & (f))

/*
 * Input control starts when we would not be able to fit the maximum
 * contents of the ping-pong buffers and finishes when we would be able
 * to fit that much plus 1/8 more.
 */
#define I_HIGH_WATER    (TTYHOG - 2 * 256)      /* XXX */
#define I_LOW_WATER     ((TTYHOG - 2 * 256) * 7 / 8)    /* XXX */

__private_extern__ void
termios32to64(struct termios32 *in, struct user_termios *out)
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

__private_extern__ void
termios64to32(struct user_termios *in, struct termios32 *out)
{
	out->c_iflag = (uint32_t)in->c_iflag;
	out->c_oflag = (uint32_t)in->c_oflag;
	out->c_cflag = (uint32_t)in->c_cflag;
	out->c_lflag = (uint32_t)in->c_lflag;

	/* bcopy is OK, since this type is ILP32/LP64 size invariant */
	bcopy(in->c_cc, out->c_cc, sizeof(in->c_cc));

	out->c_ispeed = (uint32_t)MIN(in->c_ispeed, UINT32_MAX);
	out->c_ospeed = (uint32_t)MIN(in->c_ospeed, UINT32_MAX);
}


/*
 * tty_init
 *
 * Initialize the tty line discipline subsystem.
 *
 * Parameters:	void
 *
 * Returns:	void
 *
 * Locks:	No ttys can be allocated and no tty locks can be used
 *		until after this function is called
 *
 * Notes:	The intent of this is to set up a log group attribute,
 *		lock group, and loc atribute for subsequent per-tty locks.
 *		This function is called early in bsd_init(), prior to the
 *		console device initialization.
 */
void
tty_init(void)
{
	tty_lck_grp_attr = lck_grp_attr_alloc_init();
	tty_lck_grp = lck_grp_alloc_init("tty", tty_lck_grp_attr);
	tty_lck_attr = lck_attr_alloc_init();
}


/*
 * tty_lock
 *
 * Lock the requested tty structure.
 *
 * Parameters:	tp				The tty we want to lock
 *
 * Returns:	void
 *
 * Locks:	On return, tp is locked
 */
void
tty_lock(struct tty *tp)
{
	TTY_LOCK_NOTOWNED(tp);  /* debug assert */
	lck_mtx_lock(&tp->t_lock);
}


/*
 * tty_unlock
 *
 * Unlock the requested tty structure.
 *
 * Parameters:	tp				The tty we want to unlock
 *
 * Returns:	void
 *
 * Locks:	On return, tp is unlocked
 */
void
tty_unlock(struct tty *tp)
{
	TTY_LOCK_OWNED(tp);     /* debug assert */
	lck_mtx_unlock(&tp->t_lock);
}

/*
 * ttyopen (LDISC)
 *
 * Initial open of tty, or (re)entry to standard tty line discipline.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
int
ttyopen(dev_t device, struct tty *tp)
{
	TTY_LOCK_OWNED(tp);     /* debug assert */

	tp->t_dev = device;

	if (!ISSET(tp->t_state, TS_ISOPEN)) {
		SET(tp->t_state, TS_ISOPEN);
		if (ISSET(tp->t_cflag, CLOCAL)) {
			SET(tp->t_state, TS_CONNECTED);
		}
		bzero(&tp->t_winsize, sizeof(tp->t_winsize));
	}

	return 0;
}

/*
 * ttyclose
 *
 * Handle close() on a tty line: flush and set to initial state,
 * bumping generation number so that pending read/write calls
 * can detect recycling of the tty.
 * XXX our caller should have done `spltty(); l_close(); ttyclose();'
 * and l_close() should have flushed, but we repeat the spltty() and
 * the flush in case there are buggy callers.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
int
ttyclose(struct tty *tp)
{
	struct pgrp * oldpg;
	struct session * oldsessp;
	struct knote *kn;

	TTY_LOCK_OWNED(tp);     /* debug assert */

	if (constty == tp) {
		constty = NULL;


		/*
		 * Closing current console tty; disable printing of console
		 * messages at bottom-level driver.
		 */
		(*cdevsw[major(tp->t_dev)].d_ioctl)
		(tp->t_dev, KMIOCDISABLCONS, NULL, 0, current_proc());
	}

	ttyflush(tp, FREAD | FWRITE);

	tp->t_gen++;
	tp->t_line = TTYDISC;
	proc_list_lock();
	oldpg = tp->t_pgrp;
	oldsessp = tp->t_session;
	tp->t_pgrp = NULL;
	tp->t_session = NULL;
	if (oldsessp != SESSION_NULL) {
		oldsessp->s_ttypgrpid = NO_PID;
	}
	proc_list_unlock();
	/* drop the reference on prev session and pgrp */
	/* SAFE: All callers drop the lock on return */
	tty_unlock(tp);
	if (oldsessp != SESSION_NULL) {
		session_rele(oldsessp);
	}
	if (oldpg != PGRP_NULL) {
		pg_rele(oldpg);
	}
	tty_lock(tp);
	tp->t_state = 0;
	SLIST_FOREACH(kn, &tp->t_wsel.si_note, kn_selnext) {
		KNOTE_DETACH(&tp->t_wsel.si_note, kn);
	}
	selthreadclear(&tp->t_wsel);
	SLIST_FOREACH(kn, &tp->t_rsel.si_note, kn_selnext) {
		KNOTE_DETACH(&tp->t_rsel.si_note, kn);
	}
	selthreadclear(&tp->t_rsel);

	return 0;
}

#define FLUSHQ(q) {                                                     \
	if ((q)->c_cc)                                                  \
	        ndflush(q, (q)->c_cc);                                  \
}

/* Is 'c' a line delimiter ("break" character)? */
#define TTBREAKC(c, lflag)                                                      \
	((c) == '\n' || (((c) == cc[VEOF] ||                            \
	  (c) == cc[VEOL] || ((c) == cc[VEOL2] && lflag & IEXTEN)) &&   \
	 (c) != _POSIX_VDISABLE))

/*
 * ttyinput (LDISC)
 *
 * Process input of a single character received on a tty.
 *
 * Parameters:	c			The character received
 *		tp			The tty on which it was received
 *
 * Returns:	.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
int
ttyinput(int c, struct tty *tp)
{
	tcflag_t iflag, lflag;
	cc_t *cc;
	int i, err;
	int retval = 0;                 /* default return value */

	TTY_LOCK_OWNED(tp);     /* debug assert */

	/*
	 * If input is pending take it first.
	 */
	lflag = tp->t_lflag;
	if (ISSET(lflag, PENDIN)) {
		ttypend(tp);
	}
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
	    !ISSET(tp->t_state, TS_TBLOCK)) {
		ttyblock(tp);
	}

	/* Handle exceptional conditions (break, parity, framing). */
	cc = tp->t_cc;
	err = (ISSET(c, TTY_ERRORMASK));
	if (err) {
		CLR(c, TTY_ERRORMASK);
		if (ISSET(err, TTY_BI)) {
			if (ISSET(iflag, IGNBRK)) {
				goto out;
			}
			if (ISSET(iflag, BRKINT)) {
				ttyflush(tp, FREAD | FWRITE);
				/* SAFE: All callers drop the lock on return */
				tty_unlock(tp);
				tty_pgsignal(tp, SIGINT, 1);
				tty_lock(tp);
				goto endcase;
			}
			if (ISSET(iflag, PARMRK)) {
				goto parmrk;
			}
		} else if ((ISSET(err, TTY_PE) && ISSET(iflag, INPCK))
		    || ISSET(err, TTY_FE)) {
			if (ISSET(iflag, IGNPAR)) {
				goto out;
			} else if (ISSET(iflag, PARMRK)) {
parmrk:
				if (tp->t_rawq.c_cc + tp->t_canq.c_cc >
				    MAX_INPUT - 3) {
					goto input_overflow;
				}
				(void)putc(0377 | TTY_QUOTE, &tp->t_rawq);
				(void)putc(0 | TTY_QUOTE, &tp->t_rawq);
				(void)putc(c | TTY_QUOTE, &tp->t_rawq);
				goto endcase;
			} else {
				c = 0;
			}
		}
	}

	if (!ISSET(tp->t_state, TS_TYPEN) && ISSET(iflag, ISTRIP)) {
		CLR(c, 0x80);
	}
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
					} else {
						ttyecho(c, tp);
					}
				}
				SET(tp->t_state, TS_LNCH);
				goto endcase;
			}
			if (CCEQ(cc[VDISCARD], c)) {
				if (ISSET(lflag, FLUSHO)) {
					CLR(tp->t_lflag, FLUSHO);
				} else {
					ttyflush(tp, FWRITE);
					ttyecho(c, tp);
					if (tp->t_rawq.c_cc + tp->t_canq.c_cc) {
						ttyretype(tp);
					}
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
				if (!ISSET(lflag, NOFLSH)) {
					ttyflush(tp, FREAD | FWRITE);
				}
				ttyecho(c, tp);
				/*
				 * SAFE: All callers drop the lock on return;
				 * SAFE: if we lose a threaded race on change
				 * SAFE: of the interrupt character, we could
				 * SAFE: have lost that race anyway due to the
				 * SAFE: scheduler executing threads in
				 * SAFE: priority order rather than "last
				 * SAFE: active thread" order (FEATURE).
				 */
				tty_unlock(tp);
				tty_pgsignal(tp,
				    CCEQ(cc[VINTR], c) ? SIGINT : SIGQUIT, 1);
				tty_lock(tp);
				goto endcase;
			}
			if (CCEQ(cc[VSUSP], c)) {
				if (!ISSET(lflag, NOFLSH)) {
					ttyflush(tp, FREAD);
				}
				ttyecho(c, tp);
				/* SAFE: All callers drop the lock on return */
				tty_unlock(tp);
				tty_pgsignal(tp, SIGTSTP, 1);
				tty_lock(tp);
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
					goto out;
				}
				if (!CCEQ(cc[VSTART], c)) {
					goto out;
				}
				/*
				 * if VSTART == VSTOP then toggle
				 */
				goto endcase;
			}
			if (CCEQ(cc[VSTART], c)) {
				goto restartoutput;
			}
		}
		/*
		 * IGNCR, ICRNL, & INLCR
		 */
		if (c == '\r') {
			if (ISSET(iflag, IGNCR)) {
				goto out;
			} else if (ISSET(iflag, ICRNL)) {
				c = '\n';
			}
		} else if (c == '\n' && ISSET(iflag, INLCR)) {
			c = '\r';
		}
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
			if (tp->t_rawq.c_cc) {
				if (ISSET(iflag, IUTF8)) {
					do {
						ttyrub((c = unputc(&tp->t_rawq)), tp);
					} while (tp->t_rawq.c_cc && CCONT(c));
				} else {
					ttyrub(unputc(&tp->t_rawq), tp);
				}
			}
			goto endcase;
		}
		/*
		 * kill (^U)
		 */
		if (CCEQ(cc[VKILL], c)) {
			if (ISSET(lflag, ECHOKE) &&
			    tp->t_rawq.c_cc == tp->t_rocount &&
			    !ISSET(lflag, ECHOPRT)) {
				while (tp->t_rawq.c_cc) {
					ttyrub(unputc(&tp->t_rawq), tp);
				}
			} else {
				ttyecho(c, tp);
				if (ISSET(lflag, ECHOK) ||
				    ISSET(lflag, ECHOKE)) {
					ttyecho('\n', tp);
				}
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
			while ((c = unputc(&tp->t_rawq)) == ' ' || c == '\t') {
				ttyrub(c, tp);
			}
			if (c == -1) {
				goto endcase;
			}
			/*
			 * erase last char of word and remember the
			 * next chars type (for ALTWERASE)
			 */
			ttyrub(c, tp);
			c = unputc(&tp->t_rawq);
			if (c == -1) {
				goto endcase;
			}
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
				if (c == -1) {
					goto endcase;
				}
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
			if (ISSET(lflag, ISIG)) {
				/* SAFE: All callers drop the lock on return */
				tty_unlock(tp);
				tty_pgsignal(tp, SIGINFO, 1);
				tty_lock(tp);
			}
			if (!ISSET(lflag, NOKERNINFO)) {
				ttyinfo_locked(tp);
			}
			goto endcase;
		}
	}
	/*
	 * Check for input buffer overflow
	 */
	if (tp->t_rawq.c_cc + tp->t_canq.c_cc >= MAX_INPUT) {
input_overflow:
		if (ISSET(iflag, IMAXBEL)) {
			if (tp->t_outq.c_cc < tp->t_hiwat) {
				(void)ttyoutput(CTRL('g'), tp);
			}
		}
		goto endcase;
	}

	if (c == 0377 && ISSET(iflag, PARMRK) && !ISSET(iflag, ISTRIP)
	    && ISSET(iflag, IGNBRK | IGNPAR) != (IGNBRK | IGNPAR)) {
		(void)putc(0377 | TTY_QUOTE, &tp->t_rawq);
	}

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
		} else if (tp->t_rocount++ == 0) {
			tp->t_rocol = tp->t_column;
		}
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
		goto out;
	}

restartoutput:
	CLR(tp->t_lflag, FLUSHO);
	CLR(tp->t_state, TS_TTSTOP);

startoutput:
	/* Start the output */
	retval = ttstart(tp);

out:
	return retval;
}


/*
 * ttyoutput
 *
 * Output a single character on a tty, doing output processing
 * as needed (expanding tabs, newline processing, etc.).
 *
 * Parameters:	c			The character to output
 *		tp			The tty on which to output on the tty
 *
 * Returns:	< 0			Success
 *		>= 0			Character to resend (failure)
 *
 * Locks:	Assumes tp is locked on entry, remains locked on exit
 *
 * Notes:	Must be recursive.
 */
static int
ttyoutput(int c, struct tty *tp)
{
	tcflag_t oflag;
	int col;

	TTY_LOCK_OWNED(tp);     /* debug assert */

	oflag = tp->t_oflag;
	if (!ISSET(oflag, OPOST)) {
		if (ISSET(tp->t_lflag, FLUSHO)) {
			return -1;
		}
		if (putc(c, &tp->t_outq)) {
			return c;
		}
		tk_nout++;
		tp->t_outcc++;
		return -1;
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
		col = c = 8 - (tp->t_column & 7);
		if (!ISSET(tp->t_lflag, FLUSHO)) {
			c -= b_to_q((const u_char *)"        ", c, &tp->t_outq);
			tk_nout += c;
			tp->t_outcc += c;
		}
		tp->t_column += c;
		return c == col ? -1 : '\t';
	}
	if (c == CEOT && ISSET(oflag, ONOEOT)) {
		return -1;
	}

	/*
	 * Newline translation: if ONLCR is set,
	 * translate newline into "\r\n".
	 */
	if (c == '\n' && ISSET(tp->t_oflag, ONLCR)) {
		tk_nout++;
		tp->t_outcc++;
		if (putc('\r', &tp->t_outq)) {
			return c;
		}
	}
	/* If OCRNL is set, translate "\r" into "\n". */
	else if (c == '\r' && ISSET(tp->t_oflag, OCRNL)) {
		c = '\n';
	}
	/* If ONOCR is set, don't transmit CRs when on column 0. */
	else if (c == '\r' && ISSET(tp->t_oflag, ONOCR) && tp->t_column == 0) {
		return -1;
	}
	tk_nout++;
	tp->t_outcc++;
	if (!ISSET(tp->t_lflag, FLUSHO) && putc(c, &tp->t_outq)) {
		return c;
	}

	col = tp->t_column;
	switch (CCLASS(c)) {
	case BACKSPACE:
		if (col > 0) {
			--col;
		}
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
	return -1;
}

/*
 * ttioctl
 *
 * Identical to ttioctl_locked, only the lock is not held
 *
 * Parameters:	<See ttioctl_locked()>
 *
 * Returns:	<See ttioctl_locked()>
 *
 * Locks:	This function assumes the tty_lock() is not held on entry;
 *		it takes the lock, and releases it before returning.
 *
 * Notes:	This is supported to ensure the line discipline interfaces
 *		all have the same locking semantics.
 *
 *		This function is called from
 */
int
ttioctl(struct tty *tp, u_long cmd, caddr_t data, int flag, proc_t p)
{
	int     retval;

	tty_lock(tp);
	retval = ttioctl_locked(tp, cmd, data, flag, p);
	tty_unlock(tp);

	return retval;
}


/*
 * ttioctl_locked
 *
 * Ioctls for all tty devices.
 *
 * Parameters:	tp			Tty on which ioctl() is being called
 *		cmd			ioctl() command parameter
 *		data			ioctl() data argument (if any)
 *		flag			fileglob open modes from fcntl.h;
 *					if called internally, this is usually
 *					set to 0, rather than something useful
 *		p			Process context for the call; if the
 *					call is proxied to a worker thread,
 *					this will not be the current process!!!
 *
 * Returns:	0			Success
 *		EIO			I/O error (no process group, job
 *					control, etc.)
 *		EINTR			Interrupted by signal
 *		EBUSY			Attempt to become the console while
 *					the console is busy
 *		ENOTTY			TIOCGPGRP on a non-controlling tty
 *		EINVAL			Invalid baud rate
 *		ENXIO			TIOCSETD of invalid line discipline
 *		EPERM			TIOCSTI, not root, not open for read
 *		EACCES			TIOCSTI, not root, not your controlling
 *					tty
 *		EPERM			TIOCSCTTY failed
 *		ENOTTY/EINVAL/EPERM	TIOCSPGRP failed
 *		EPERM			TIOCSDRAINWAIT as non-root user
 *	suser:EPERM			Console control denied
 *	ttywait:EIO			t_timeout too small/expired
 *	ttywait:ERESTART		Upper layer must redrive the call;
 *					this is usually done by the Libc
 *					stub in user space
 *	ttywait:EINTR			Interrupted (usually a signal)
 *	ttcompat:EINVAL
 *	ttcompat:ENOTTY
 *	ttcompat:EIOCTL
 *	ttcompat:ENOTTY			TIOCGSID, if no session or session
 *					leader
 *	ttcompat:ENOTTY			All unrecognized ioctls
 *	*tp->t_param:?			TIOCSETA* underlying function
 *	*linesw[t].l_open:?		TIOCSETD line discipline open failure
 *
 *
 * Locks:	This function assumes that the tty_lock() is held for the
 *		tp at the time of the call.  The lock remains held on return.
 *
 * Notes:	This function is called after line-discipline specific ioctl
 *		has been called to do discipline-specific functions and/or
 *		reject any of these ioctl() commands.
 *
 *		This function calls ttcompat(), which can re-call ttioctl()
 *		to a depth of one (FORTRAN style mutual recursion); at some
 *		point, we should just in-line ttcompat() here.
 */
int
ttioctl_locked(struct tty *tp, u_long cmd, caddr_t data, int flag, proc_t p)
{
	int error = 0;
	int bogusData = 1;
	struct uthread *ut;
	struct pgrp *pg, *oldpg;
	struct session *sessp, *oldsessp;
	struct tty *oldtp;

	TTY_LOCK_OWNED(tp);     /* debug assert */

	ut = (struct uthread *)get_bsdthread_info(current_thread());
	/* If the ioctl involves modification, signal if in the background. */
	switch (cmd) {
	case TIOCIXON:
	case TIOCIXOFF:
	case  TIOCDRAIN:
	case  TIOCFLUSH:
	case TIOCSTOP:
	case TIOCSTART:
	case  TIOCSETA_32:
	case  TIOCSETA_64:
	case  TIOCSETD:
	case  TIOCSETAF_32:
	case  TIOCSETAF_64:
	case  TIOCSETAW_32:
	case  TIOCSETAW_64:
	case  TIOCSPGRP:
	case  TIOCSTAT:
	case  TIOCSTI:
	case  TIOCSWINSZ:
	case  TIOCLBIC:
	case  TIOCLBIS:
	case  TIOCLSET:
	case  TIOCSETC:
	case OTIOCSETD:
	case  TIOCSETN:
	case  TIOCSETP:
	case  TIOCSLTC:
		while (isbackground(p, tp) &&
		    (p->p_lflag & P_LPPWAIT) == 0 &&
		    (p->p_sigignore & sigmask(SIGTTOU)) == 0 &&
		    (ut->uu_sigmask & sigmask(SIGTTOU)) == 0) {
			pg = proc_pgrp(p);
			if (pg == PGRP_NULL) {
				error = EIO;
				goto out;
			}
			/* SAFE: All callers drop the lock on return */
			tty_unlock(tp);
			if (pg->pg_jobc == 0) {
				pg_rele(pg);
				tty_lock(tp);
				error = EIO;
				goto out;
			}
			pgsignal(pg, SIGTTOU, 1);
			pg_rele(pg);
			tty_lock(tp);


			/*
			 * We signalled ourself, so we need to act as if we
			 * have been "interrupted" from a "sleep" to act on
			 * the signal.  If it's a signal that stops the
			 * process, that's handled in the signal sending code.
			 */
			error = EINTR;
			goto out;
		}
		break;
	}

	switch (cmd) {                  /* Process the ioctl. */
	case FIOASYNC:                  /* set/clear async i/o */
		if (*(int *)data) {
			SET(tp->t_state, TS_ASYNC);
		} else {
			CLR(tp->t_state, TS_ASYNC);
		}
		break;
	case FIONBIO:                   /* set/clear non-blocking i/o */
		break;                  /* XXX: delete. */
	case FIONREAD:                  /* get # bytes to read */
		*(int *)data = ttnread(tp);
		break;
	case TIOCEXCL:                  /* set exclusive use of tty */
		SET(tp->t_state, TS_XCLUDE);
		break;
	case TIOCFLUSH: {               /* flush buffers */
		int flags = *(int *)data;

		if (flags == 0) {
			flags = FREAD | FWRITE;
		} else {
			flags &= FREAD | FWRITE;
		}
		ttyflush(tp, flags);
		break;
	}
	case TIOCSCONS: {
		/* Set current console device to this line */
		data = (caddr_t) &bogusData;
	}
		OS_FALLTHROUGH;
	case TIOCCONS: {                        /* become virtual console */
		if (*(int *)data) {
			if (constty && constty != tp &&
			    ISSET(constty->t_state, TS_CONNECTED)) {
				error = EBUSY;
				goto out;
			}
			if ((error = suser(kauth_cred_get(), &p->p_acflag))) {
				goto out;
			}
			constty = tp;
		} else if (tp == constty) {
			constty = NULL;
		}
		if (constty) {
			(*cdevsw[major(constty->t_dev)].d_ioctl)
			(constty->t_dev, KMIOCDISABLCONS, NULL, 0, p);
		} else {
			(*cdevsw[major(tp->t_dev)].d_ioctl)
			(tp->t_dev, KMIOCDISABLCONS, NULL, 0, p);
		}
		break;
	}
	case TIOCDRAIN:                 /* wait till output drained */
		error = ttywait(tp);
		if (error) {
			goto out;
		}
		break;
	case TIOCGETA_32:               /* get termios struct */
#ifdef __LP64__
		termios64to32((struct user_termios *)&tp->t_termios, (struct termios32 *)data);
#else
		bcopy(&tp->t_termios, data, sizeof(struct termios));
#endif
		break;
	case TIOCGETA_64:               /* get termios struct */
#ifdef __LP64__
		bcopy(&tp->t_termios, data, sizeof(struct termios));
#else
		termios32to64((struct termios32 *)&tp->t_termios, (struct user_termios *)data);
#endif
		break;
	case TIOCGETD:                  /* get line discipline */
		*(int *)data = tp->t_line;
		break;
	case TIOCGWINSZ:                /* get window size */
		*(struct winsize *)data = tp->t_winsize;
		break;
	case TIOCGPGRP:                 /* get pgrp of tty */
		if (!isctty(p, tp)) {
			error = ENOTTY;
			goto out;
		}
		*(int *)data = tp->t_pgrp ? tp->t_pgrp->pg_id : NO_PID;
		break;
#ifdef TIOCHPCL
	case TIOCHPCL:                  /* hang up on last close */
		SET(tp->t_cflag, HUPCL);
		break;
#endif
	case TIOCNXCL:                  /* reset exclusive use of tty */
		CLR(tp->t_state, TS_XCLUDE);
		break;
	case TIOCOUTQ:                  /* output queue size */
		*(int *)data = tp->t_outq.c_cc;
		break;
	case TIOCSETA_32:                       /* set termios struct */
	case TIOCSETA_64:
	case TIOCSETAW_32:                      /* drain output, set */
	case TIOCSETAW_64:
	case TIOCSETAF_32:              /* drn out, fls in, set */
	case TIOCSETAF_64:
	{               /* drn out, fls in, set */
		struct termios *t = (struct termios *)data;
		struct termios lcl_termios;

#ifdef __LP64__
		if (cmd == TIOCSETA_32 || cmd == TIOCSETAW_32 || cmd == TIOCSETAF_32) {
			termios32to64((struct termios32 *)data, (struct user_termios *)&lcl_termios);
			t = &lcl_termios;
		}
#else
		if (cmd == TIOCSETA_64 || cmd == TIOCSETAW_64 || cmd == TIOCSETAF_64) {
			termios64to32((struct user_termios *)data, (struct termios32 *)&lcl_termios);
			t = &lcl_termios;
		}
#endif
#if 0
		/* XXX bogus test; always false */
		if (t->c_ispeed < 0 || t->c_ospeed < 0) {
			error = EINVAL;
			goto out;
		}
#endif  /* 0 - leave in; may end up being a conformance issue */
		if (t->c_ispeed == 0) {
			t->c_ispeed = t->c_ospeed;
		}
		if (cmd == TIOCSETAW_32 || cmd == TIOCSETAF_32 ||
		    cmd == TIOCSETAW_64 || cmd == TIOCSETAF_64) {
			error = ttywait(tp);
			if (error) {
				goto out;
			}
			if (cmd == TIOCSETAF_32 || cmd == TIOCSETAF_64) {
				ttyflush(tp, FREAD);
			}
		}
		if (!ISSET(t->c_cflag, CIGNORE)) {
			/*
			 * Set device hardware.
			 */
			if (tp->t_param && (error = (*tp->t_param)(tp, t))) {
				goto out;
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
			    !ISSET(tp->t_state, TS_ZOMBIE)) {
				SET(tp->t_state, TS_CONNECTED);
			} else {
				CLR(tp->t_state, TS_CONNECTED);
			}
			tp->t_cflag = t->c_cflag;
			tp->t_ispeed = t->c_ispeed;
			tp->t_ospeed = t->c_ospeed;
			ttsetwater(tp);
		}
		if (ISSET(t->c_lflag, ICANON) != ISSET(tp->t_lflag, ICANON) &&
		    cmd != TIOCSETAF_32 && cmd != TIOCSETAF_64) {
			if (ISSET(t->c_lflag, ICANON)) {
				SET(tp->t_lflag, PENDIN);
			} else {
				/*
				 * XXX we really shouldn't allow toggling
				 * ICANON while we're in a non-termios line
				 * discipline.  Now we have to worry about
				 * panicing for a null queue.
				 */
				if (tp->t_rawq.c_cs && tp->t_canq.c_cs) {
					struct clist tq;

					catq(&tp->t_rawq, &tp->t_canq);
					tq = tp->t_rawq;
					tp->t_rawq = tp->t_canq;
					tp->t_canq = tq;
				}
				CLR(tp->t_lflag, PENDIN);
			}
			ttwakeup(tp);
		}
		tp->t_iflag = t->c_iflag;
		tp->t_oflag = t->c_oflag;
		/*
		 * Make the EXTPROC bit read only.
		 */
		if (ISSET(tp->t_lflag, EXTPROC)) {
			SET(t->c_lflag, EXTPROC);
		} else {
			CLR(t->c_lflag, EXTPROC);
		}
		tp->t_lflag = t->c_lflag | ISSET(tp->t_lflag, PENDIN);
		if (t->c_cc[VMIN] != tp->t_cc[VMIN] ||
		    t->c_cc[VTIME] != tp->t_cc[VTIME]) {
			ttwakeup(tp);
		}
		bcopy(t->c_cc, tp->t_cc, sizeof(t->c_cc));
		break;
	}
	case TIOCSETD: {                /* set line discipline */
		int t = *(int *)data;
		dev_t device = tp->t_dev;

		if (t >= nlinesw || t < 0) {
			error = ENXIO;
			goto out;
		}
		/*
		 * If the new line discipline is not equal to the old one,
		 * close the old one and open the new one.
		 */
		if (t != tp->t_line) {
			(*linesw[tp->t_line].l_close)(tp, flag);
			error = (*linesw[t].l_open)(device, tp);
			if (error) {
				/* This is racy; it's possible to lose both */
				(void)(*linesw[tp->t_line].l_open)(device, tp);
				goto out;
			}
			tp->t_line = t;
		}
		break;
	}
	case TIOCSTART:                 /* start output, like ^Q */
		if (ISSET(tp->t_state, TS_TTSTOP) ||
		    ISSET(tp->t_lflag, FLUSHO)) {
			CLR(tp->t_lflag, FLUSHO);
			CLR(tp->t_state, TS_TTSTOP);
			ttstart(tp);
		}
		break;
	case TIOCSTI:                   /* simulate terminal input */
		if (suser(kauth_cred_get(), NULL) && (flag & FREAD) == 0) {
			error = EPERM;
			goto out;
		}
		if (suser(kauth_cred_get(), NULL) && !isctty(p, tp)) {
			error = EACCES;
			goto out;
		}
		(*linesw[tp->t_line].l_rint)(*(u_char *)data, tp);
		break;
	case TIOCSTOP:                  /* stop output, like ^S */
		if (!ISSET(tp->t_state, TS_TTSTOP)) {
			SET(tp->t_state, TS_TTSTOP);
			ttystop(tp, 0);
		}
		break;
	case TIOCIXON:
		ttyunblock(tp);
		break;
	case TIOCIXOFF:
		ttyblock(tp);
		break;
	case TIOCSCTTY:                 /* become controlling tty */
		/* Session ctty vnode pointer set in vnode layer. */
		sessp = proc_session(p);
		if (sessp == SESSION_NULL) {
			error = EPERM;
			goto out;
		}

		/*
		 * This can only be done by a session leader.
		 */
		if (!SESS_LEADER(p, sessp)) {
			/* SAFE: All callers drop the lock on return */
			tty_unlock(tp);
			session_rele(sessp);
			tty_lock(tp);
			error = EPERM;
			goto out;
		}
		/*
		 * If this terminal is already the controlling terminal for the
		 * session, nothing to do here.
		 */
		if (tp->t_session == sessp) {
			/* SAFE: All callers drop the lock on return */
			tty_unlock(tp);
			session_rele(sessp);
			tty_lock(tp);
			error = 0;
			goto out;
		}
		pg = proc_pgrp(p);
		/*
		 * Deny if the terminal is already attached to another session or
		 * the session already has a terminal vnode.
		 */
		session_lock(sessp);
		if (sessp->s_ttyvp || tp->t_session) {
			session_unlock(sessp);
			/* SAFE: All callers drop the lock on return */
			tty_unlock(tp);
			if (pg != PGRP_NULL) {
				pg_rele(pg);
			}
			session_rele(sessp);
			tty_lock(tp);
			error = EPERM;
			goto out;
		}
		sessp->s_ttypgrpid = pg->pg_id;
		oldtp = sessp->s_ttyp;
		ttyhold(tp);
		sessp->s_ttyp = tp;
		session_unlock(sessp);
		proc_list_lock();
		oldsessp = tp->t_session;
		oldpg = tp->t_pgrp;
		if (oldsessp != SESSION_NULL) {
			oldsessp->s_ttypgrpid = NO_PID;
		}
		/* do not drop refs on sessp and pg as tp holds them */
		tp->t_session = sessp;
		tp->t_pgrp = pg;
		proc_list_unlock();
		OSBitOrAtomic(P_CONTROLT, &p->p_flag);
		/* SAFE: All callers drop the lock on return */
		tty_unlock(tp);
		/* drop the reference on prev session and pgrp */
		if (oldsessp != SESSION_NULL) {
			session_rele(oldsessp);
		}
		if (oldpg != PGRP_NULL) {
			pg_rele(oldpg);
		}
		if (NULL != oldtp) {
			ttyfree(oldtp);
		}
		tty_lock(tp);
		break;

	case TIOCSPGRP: {               /* set pgrp of tty */
		struct pgrp *pgrp = PGRP_NULL;

		sessp = proc_session(p);
		if (!isctty_sp(p, tp, sessp)) {
			if (sessp != SESSION_NULL) {
				session_rele(sessp);
			}
			error = ENOTTY;
			goto out;
		} else if ((pgrp = pgfind(*(int *)data)) == PGRP_NULL) {
			if (sessp != SESSION_NULL) {
				session_rele(sessp);
			}
			error = EINVAL;
			goto out;
		} else if (pgrp->pg_session != sessp) {
			/* SAFE: All callers drop the lock on return */
			tty_unlock(tp);
			if (sessp != SESSION_NULL) {
				session_rele(sessp);
			}
			pg_rele(pgrp);
			tty_lock(tp);
			error = EPERM;
			goto out;
		}

		proc_list_lock();
		oldpg = tp->t_pgrp;
		tp->t_pgrp = pgrp;
		sessp->s_ttypgrpid = pgrp->pg_id;
		proc_list_unlock();

		/*
		 * Wakeup readers to recheck if they are still the foreground
		 * process group.
		 *
		 * ttwakeup() isn't called because the readers aren't getting
		 * woken up because there is something to read but to force
		 * the re-evaluation of their foreground process group status.
		 *
		 * Ordinarily leaving these readers waiting wouldn't be an issue
		 * as launchd would send them a termination signal eventually
		 * (if nobody else does). But if this terminal happens to be
		 * /dev/console, launchd itself could get blocked forever behind
		 * a revoke of /dev/console and leave the system deadlocked.
		 */
		wakeup(TSA_HUP_OR_INPUT(tp));

		/* SAFE: All callers drop the lock on return */
		tty_unlock(tp);
		if (oldpg != PGRP_NULL) {
			pg_rele(oldpg);
		}
		if (sessp != SESSION_NULL) {
			session_rele(sessp);
		}
		tty_lock(tp);
		break;
	}
	case TIOCSTAT:                  /* simulate control-T */
		ttyinfo_locked(tp);
		break;
	case TIOCSWINSZ:                /* set window size */
		if (bcmp((caddr_t)&tp->t_winsize, data,
		    sizeof(struct winsize))) {
			tp->t_winsize = *(struct winsize *)data;
			/* SAFE: All callers drop the lock on return */
			tty_unlock(tp);
			tty_pgsignal(tp, SIGWINCH, 1);
			tty_lock(tp);
		}
		break;
	case TIOCSDRAINWAIT:
		error = suser(kauth_cred_get(), &p->p_acflag);
		if (error) {
			goto out;
		}
		tp->t_timeout = *(int *)data * hz;
		wakeup(TSA_OCOMPLETE(tp));
		wakeup(TSA_OLOWAT(tp));
		break;
	case TIOCGDRAINWAIT:
		*(int *)data = tp->t_timeout / hz;
		break;
	case TIOCREVOKE:
		SET(tp->t_state, TS_REVOKE);
		tp->t_gen++;
		/*
		 * At this time, only this wait channel is woken up as only
		 * ttread has been problematic. It is possible we may need
		 * to add wake up other tty wait addresses as well.
		 */
		wakeup(TSA_HUP_OR_INPUT(tp));
		break;
	case TIOCREVOKECLEAR:
		CLR(tp->t_state, TS_REVOKE);
		break;
	default:
		error = ttcompat(tp, cmd, data, flag, p);
		goto out;
	}

	error = 0;
out:
	return error;
}


/*
 * Locks:	Assumes tp is locked on entry, remains locked on exit
 */
int
ttyselect(struct tty *tp, int rw, void *wql, proc_t p)
{
	int retval = 0;
	/*
	 * Attaching knotes to TTYs needs to call selrecord in order to hook
	 * up the waitq to the selinfo, regardless of data being ready.  See
	 * filt_ttyattach.
	 */
	bool needs_selrecord = rw & FMARK;
	rw &= ~FMARK;

	if (tp == NULL) {
		return ENXIO;
	}

	TTY_LOCK_OWNED(tp);

	if (tp->t_state & TS_ZOMBIE) {
		retval = 1;
		goto out;
	}

	switch (rw) {
	case FREAD:
		retval = ttnread(tp);
		if (retval > 0) {
			break;
		}

		selrecord(p, &tp->t_rsel, wql);
		break;
	case FWRITE:
		if ((tp->t_outq.c_cc <= tp->t_lowat) &&
		    (tp->t_state & TS_CONNECTED)) {
			retval = tp->t_hiwat - tp->t_outq.c_cc;
			break;
		}

		selrecord(p, &tp->t_wsel, wql);
		break;
	}

out:
	if (retval > 0 && needs_selrecord) {
		switch (rw) {
		case FREAD:
			selrecord(p, &tp->t_rsel, wql);
			break;
		case FWRITE:
			selrecord(p, &tp->t_wsel, wql);
			break;
		}
	}

	return retval;
}


/*
 * This is a wrapper for compatibility with the select vector used by
 * cdevsw.  It relies on a proper xxxdevtotty routine.
 *
 * Locks:	Assumes tty_lock() is not held prior to calling.
 */
int
ttselect(dev_t dev, int rw, void *wql, proc_t p)
{
	int     rv;
	struct tty *tp = cdevsw[major(dev)].d_ttys[minor(dev)];

	tty_lock(tp);
	rv =  ttyselect(tp, rw, wql, p);
	tty_unlock(tp);

	return rv;
}


/*
 * Locks:	Assumes tp is locked on entry, remains locked on exit
 */
__private_extern__ int
ttnread(struct tty *tp)
{
	int nread;

	TTY_LOCK_OWNED(tp);     /* debug assert */

	if (ISSET(tp->t_lflag, PENDIN)) {
		ttypend(tp);
	}
	nread = tp->t_canq.c_cc;
	if (!ISSET(tp->t_lflag, ICANON)) {
		nread += tp->t_rawq.c_cc;
		if (nread < tp->t_cc[VMIN] && tp->t_cc[VTIME] == 0) {
			nread = 0;
		}
	}
	return nread;
}


/*
 * ttywait
 *
 * Wait for output to drain.
 *
 * Parameters:	tp			Tty on which to wait for output to drain
 *
 * Returns:	0			Success
 *		EIO			t_timeout too small/expired
 *	ttysleep:ERESTART		Upper layer must redrive the call;
 *					this is usually done by the Libc
 *					stub in user space
 *	ttysleep:EINTR			Interrupted (usually a signal)
 *
 * Notes:	Called from proc_exit() and vproc_exit().
 *
 * Locks:	Assumes tp is locked on entry, remains locked on exit
 */
int
ttywait(struct tty *tp)
{
	int error;

	TTY_LOCK_OWNED(tp);     /* debug assert */

	error = 0;
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
				if (error == EWOULDBLOCK) {
					error = EIO;
				}
				break;
			}
		} else {
			break;
		}
	}
	if (!error && (tp->t_outq.c_cc || ISSET(tp->t_state, TS_BUSY))) {
		error = EIO;
	}
	return error;
}

/*
 * Stop the underlying device driver.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
static void
ttystop(struct tty *tp, int rw)
{
	TTY_LOCK_OWNED(tp);     /* debug assert */

	(*cdevsw[major(tp->t_dev)].d_stop)(tp, rw);
}

/*
 * Flush if successfully wait.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
static int
ttywflush(struct tty *tp)
{
	int error;

	TTY_LOCK_OWNED(tp);     /* debug assert */

	if ((error = ttywait(tp)) == 0) {
		ttyflush(tp, FREAD);
	}
	return error;
}

/*
 * Flush tty read and/or write queues, notifying anyone waiting.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
void
ttyflush(struct tty *tp, int rw)
{
	TTY_LOCK_OWNED(tp);     /* debug assert */

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
			if (rw & FWRITE) {
				FLUSHQ(&tp->t_outq);
			}
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
}

/*
 * Copy in the default termios characters.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 *
 * Notes:	No assertion; tp is not in scope.
 */
void
termioschars(struct termios *t)
{
	bcopy(ttydefchars, t->c_cc, sizeof t->c_cc);
}


/*
 * Handle input high water.  Send stop character for the IXOFF case.  Turn
 * on our input flow control bit and propagate the changes to the driver.
 * XXX the stop character should be put in a special high priority queue.
 *
 * Locks:	Assumes tty_lock() is held for the call.
 */
void
ttyblock(struct tty *tp)
{
	TTY_LOCK_OWNED(tp);     /* debug assert */

	SET(tp->t_state, TS_TBLOCK);
	if (ISSET(tp->t_iflag, IXOFF) && tp->t_cc[VSTOP] != _POSIX_VDISABLE &&
	    putc(tp->t_cc[VSTOP], &tp->t_outq) != 0) {
		CLR(tp->t_state, TS_TBLOCK);    /* try again later */
	}
	ttstart(tp);
}


/*
 * Handle input low water.  Send start character for the IXOFF case.  Turn
 * off our input flow control bit and propagate the changes to the driver.
 * XXX the start character should be put in a special high priority queue.
 *
 * Locks:	Assumes tty_lock() is held for the call.
 */
static void
ttyunblock(struct tty *tp)
{
	TTY_LOCK_OWNED(tp);     /* debug assert */

	CLR(tp->t_state, TS_TBLOCK);
	if (ISSET(tp->t_iflag, IXOFF) && tp->t_cc[VSTART] != _POSIX_VDISABLE &&
	    putc(tp->t_cc[VSTART], &tp->t_outq) != 0) {
		SET(tp->t_state, TS_TBLOCK);    /* try again later */
	}
	ttstart(tp);
}


/*
 * ttstart
 *
 * Start tty output
 *
 * Parameters:	tp			tty on which to start output
 *
 * Returns:	0			Success
 *
 * Locks:	Assumes tty_lock() is held for the call.
 *
 * Notes:	This function might as well be void; it always returns success
 *
 *		Called from ttioctl_locked(), LDISC routines, and
 *		ttycheckoutq(), ttyblock(), ttyunblock(), and tputchar()
 */
int
ttstart(struct tty *tp)
{
	TTY_LOCK_OWNED(tp);     /* debug assert */

	if (tp->t_oproc != NULL) {      /* XXX: Kludge for pty. */
		(*tp->t_oproc)(tp);
	}

	return 0;
}


/*
 * ttylclose (LDISC)
 *
 * "close" a line discipline
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
int
ttylclose(struct tty *tp, int flag)
{
	TTY_LOCK_OWNED(tp);     /* debug assert */

	if ((flag & FNONBLOCK) || ttywflush(tp)) {
		ttyflush(tp, FREAD | FWRITE);
	}

	return 0;
}


/*
 * ttymodem (LDISC)
 *
 * Handle modem control transition on a tty.
 * Flag indicates new state of carrier.
 * Returns 0 if the line should be turned off, otherwise 1.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
int
ttymodem(struct tty *tp, int flag)
{
	int rval = 1;           /* default return value */

	TTY_LOCK_OWNED(tp);     /* debug assert */

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
			if (tp->t_session && tp->t_session->s_leader) {
				psignal(tp->t_session->s_leader, SIGHUP);
			}
			ttyflush(tp, FREAD | FWRITE);
			rval = 0;
			goto out;
		}
	} else {
		/*
		 * Carrier now on.
		 */
		SET(tp->t_state, TS_CARR_ON);
		if (!ISSET(tp->t_state, TS_ZOMBIE)) {
			SET(tp->t_state, TS_CONNECTED);
		}
		wakeup(TSA_CARR_ON(tp));
		ttwakeup(tp);
		ttwwakeup(tp);
	}

out:
	return rval;
}


/*
 * Reinput pending characters after state switch
 * call at spltty().
 *
 * Locks:	Assumes tty_lock() is held for the call.
 */
static void
ttypend(struct tty *tp)
{
	struct clist tq;
	int c;

	TTY_LOCK_OWNED(tp);     /* debug assert */

	CLR(tp->t_lflag, PENDIN);
	SET(tp->t_state, TS_TYPEN);
	tq = tp->t_rawq;
	tp->t_rawq.c_cc = 0;
	tp->t_rawq.c_cf = tp->t_rawq.c_cl = NULL;
	while ((c = getc(&tq)) >= 0) {
		ttyinput(c, tp);
	}
	CLR(tp->t_state, TS_TYPEN);
}


/*
 * ttread (LDISC)
 *
 * Process a read call on a tty device.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
int
ttread(struct tty *tp, struct uio *uio, int flag)
{
	struct clist *qp;
	int c;
	tcflag_t lflag;
	cc_t *cc = tp->t_cc;
	proc_t p = current_proc();
	int first, error = 0;
	int has_etime = 0, last_cc = 0;
	long slp = 0;           /* XXX this should be renamed `timo'. */
	struct uthread *ut;
	struct pgrp * pg;

	TTY_LOCK_OWNED(tp);     /* debug assert */

	ut = (struct uthread *)get_bsdthread_info(current_thread());

loop:
	lflag = tp->t_lflag;
	/*
	 * take pending input first
	 */
	if (ISSET(lflag, PENDIN)) {
		ttypend(tp);
		lflag = tp->t_lflag;    /* XXX ttypend() clobbers it */
	}

	/*
	 * Signal the process if it's in the background. If the terminal is
	 * getting revoked, everybody is in the background.
	 */
	if (isbackground(p, tp) || ISSET(tp->t_state, TS_REVOKE)) {
		if ((p->p_sigignore & sigmask(SIGTTIN)) ||
		    (ut->uu_sigmask & sigmask(SIGTTIN)) ||
		    p->p_lflag & P_LPPWAIT) {
			error = EIO;
			goto err;
		}
		pg = proc_pgrp(p);
		if (pg == PGRP_NULL) {
			error = EIO;
			goto err;
		}
		if (pg->pg_jobc == 0) {
			/* SAFE: All callers drop the lock on return */
			tty_unlock(tp);
			pg_rele(pg);
			tty_lock(tp);
			error = EIO;
			goto err;
		}
		/* SAFE: All callers drop the lock on return */
		tty_unlock(tp);
		pgsignal(pg, SIGTTIN, 1);
		pg_rele(pg);
		tty_lock(tp);

		/*
		 * We signalled ourself, so we need to act as if we
		 * have been "interrupted" from a "sleep" to act on
		 * the signal.  If it's a signal that stops the
		 * process, that's handled in the signal sending code.
		 */
		error = EINTR;
		goto err;
	}

	if (ISSET(tp->t_state, TS_ZOMBIE)) {
		/* EOF - returning 0 */
		goto err;
	}

	/*
	 * If canonical, use the canonical queue,
	 * else use the raw queue.
	 *
	 * (should get rid of clists...)
	 */
	qp = ISSET(lflag, ICANON) ? &tp->t_canq : &tp->t_rawq;

	if (flag & IO_NDELAY) {
		if (qp->c_cc > 0) {
			goto read;
		}
		if (ISSET(lflag, ICANON) || cc[VMIN] != 0) {
			error = EWOULDBLOCK;
		}
		/* else polling - returning 0 */
		goto err;
	}
	if (!ISSET(lflag, ICANON)) {
		int m = cc[VMIN];
		long t = cc[VTIME];
		struct timeval timecopy;
		struct timeval etime = {.tv_sec = 0, .tv_usec = 0};     /* protected by !has_etime */

		/*
		 * Check each of the four combinations.
		 * (m > 0 && t == 0) is the normal read case.
		 * It should be fairly efficient, so we check that and its
		 * companion case (m == 0 && t == 0) first.
		 * For the other two cases, we compute the target sleep time
		 * into slp.
		 */
		if (t == 0) {
			if (qp->c_cc < m) {
				goto sleep;
			}
			if (qp->c_cc > 0) {
				goto read;
			}

			/* m, t and qp->c_cc are all 0.  0 is enough input. */
			goto err;
		}
		t *= 100000;            /* time in us */
#define diff(t1, t2) (((t1).tv_sec - (t2).tv_sec) * 1000000 + \
	                 ((t1).tv_usec - (t2).tv_usec))
		if (m > 0) {
			if (qp->c_cc <= 0) {
				goto sleep;
			}
			if (qp->c_cc >= m) {
				goto read;
			}
			microuptime(&timecopy);
			if (!has_etime || qp->c_cc > last_cc) {
				/* first character or got a character, start timer */
				has_etime = 1;

				etime.tv_sec = t / 1000000;
				etime.tv_usec =
				    (__darwin_suseconds_t)(t - (etime.tv_sec * 1000000));
				timeradd(&etime, &timecopy, &etime);

				slp = t;
			} else {
				/* nothing, check expiration */
				if (timercmp(&etime, &timecopy, <=)) {
					goto read;
				}

				slp = diff(etime, timecopy);
			}
			last_cc = qp->c_cc;
		} else {        /* m == 0 */
			if (qp->c_cc > 0) {
				goto read;
			}
			microuptime(&timecopy);
			if (!has_etime) {
				has_etime = 1;

				etime.tv_sec = t / 1000000;
				etime.tv_usec =
				    (__darwin_suseconds_t)(t - (etime.tv_sec * 1000000));
				timeradd(&etime, &timecopy, &etime);

				slp = t;
			} else {
				if (timercmp(&etime, &timecopy, <=)) {
					/* Timed out, but 0 is enough input. */
					goto err;
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
		slp = (long) (((u_int32_t)slp * hz) + 999999) / 1000000;
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
		if (error == EWOULDBLOCK) {
			error = 0;
		} else if (error) {
			goto err;
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
	/*
	 * Input present, check for input mapping and processing.
	 */
	first = 1;
	if (ISSET(lflag, ICANON)
	    || (ISSET(lflag, IEXTEN | ISIG) == (IEXTEN | ISIG))) {
		goto slowcase;
	}
	for (;;) {
		char ibuf[IBUFSIZ];
		int icc;
		ssize_t size = uio_resid(uio);
		if (size < 0) {
			error = ERANGE;
			break;
		}

		icc = (int)MIN(size, IBUFSIZ);
		icc = q_to_b(qp, (u_char *)ibuf, icc);
		if (icc <= 0) {
			if (first) {
				goto loop;
			}
			break;
		}
		error = uiomove(ibuf, icc, uio);
		/*
		 * XXX if there was an error then we should ungetc() the
		 * unmoved chars and reduce icc here.
		 */
		if (error) {
			break;
		}
		if (uio_resid(uio) == 0) {
			break;
		}
		first = 0;
	}
	goto out;
slowcase:
	for (;;) {
		c = getc(qp);
		if (c < 0) {
			if (first) {
				goto loop;
			}
			break;
		}
		/*
		 * delayed suspend (^Y)
		 */
		if (CCEQ(cc[VDSUSP], c) &&
		    ISSET(lflag, IEXTEN | ISIG) == (IEXTEN | ISIG)) {
			/*
			 * SAFE: All callers drop the lock on return and
			 * SAFE: current thread will not change out from
			 * SAFE: under us in the "goto loop" case.
			 */
			tty_unlock(tp);
			tty_pgsignal(tp, SIGTSTP, 1);
			tty_lock(tp);
			if (first) {
				error = ttysleep(tp, &ttread, TTIPRI | PCATCH,
				    "ttybg3", hz);
				if (error) {
					break;
				}
				goto loop;
			}
			break;
		}
		/*
		 * Interpret EOF only in canonical mode.
		 */
		if (CCEQ(cc[VEOF], c) && ISSET(lflag, ICANON)) {
			break;
		}
		/*
		 * Give user character.
		 */
		error = ureadc(c, uio);
		if (error) {
			/* XXX should ungetc(c, qp). */
			break;
		}
		if (uio_resid(uio) == 0) {
			break;
		}
		/*
		 * In canonical mode check for a "break character"
		 * marking the end of a "line of input".
		 */
		if (ISSET(lflag, ICANON) && TTBREAKC(c, lflag)) {
			break;
		}
		first = 0;
	}

out:
	/*
	 * Look to unblock input now that (presumably)
	 * the input queue has gone down.
	 */
	if (ISSET(tp->t_state, TS_TBLOCK) &&
	    tp->t_rawq.c_cc + tp->t_canq.c_cc <= I_LOW_WATER) {
		ttyunblock(tp);
	}

err:
	return error;
}


/*
 * Check the output queue on tp for space for a kernel message (from uprintf
 * or tprintf).  Allow some space over the normal hiwater mark so we don't
 * lose messages due to normal flow control, but don't let the tty run amok.
 * Sleeps here are not interruptible, but we return prematurely if new signals
 * arrive.
 *
 * Locks:	Assumes tty_lock() is held before calling
 *
 * Notes:	This function is called from tprintf() in subr_prf.c
 */
int
ttycheckoutq(struct tty *tp, int wait)
{
	int hiwat;
	sigset_t oldsig;
	struct uthread *ut;

	TTY_LOCK_OWNED(tp);     /* debug assert */

	ut = (struct uthread *)get_bsdthread_info(current_thread());

	hiwat = tp->t_hiwat;
	oldsig = wait ? ut->uu_siglist : 0;
	if (tp->t_outq.c_cc > hiwat + OBUFSIZ + 100) {
		while (tp->t_outq.c_cc > hiwat) {
			ttstart(tp);
			if (tp->t_outq.c_cc <= hiwat) {
				break;
			}
			if (wait == 0 || ut->uu_siglist != oldsig) {
				return 0;
			}
			SET(tp->t_state, TS_SO_OLOWAT);
			ttysleep(tp, TSA_OLOWAT(tp), PZERO - 1, "ttoutq", hz);
		}
	}
	return 1;
}


/*
 * ttwrite (LDISC)
 *
 * Process a write call on a tty device.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
int
ttwrite(struct tty *tp, struct uio *uio, int flag)
{
	char *cp = NULL;
	int cc, ce;
	proc_t p;
	int i, hiwat, error;
	user_ssize_t count;
	char obuf[OBUFSIZ];
	struct uthread *ut;
	struct pgrp * pg;

	TTY_LOCK_OWNED(tp);     /* debug assert */

	ut = (struct uthread *)get_bsdthread_info(current_thread());
	hiwat = tp->t_hiwat;
	count = uio_resid(uio);
	error = 0;
	cc = 0;
loop:
	if (ISSET(tp->t_state, TS_ZOMBIE)) {
		if (uio_resid(uio) == count) {
			error = EIO;
		}
		goto out;
	}
	if (!ISSET(tp->t_state, TS_CONNECTED)) {
		if (flag & IO_NDELAY) {
			error = EWOULDBLOCK;
			goto out;
		}
		error = ttysleep(tp, TSA_CARR_ON(tp), TTIPRI | PCATCH,
		    "ttydcd", 0);
		if (error) {
			goto out;
		}
		goto loop;
	}
	/*
	 * Signal the process if it's in the background.
	 */
	p = current_proc();
	if (isbackground(p, tp) &&
	    ISSET(tp->t_lflag, TOSTOP) && (p->p_lflag & P_LPPWAIT) == 0 &&
	    (p->p_sigignore & sigmask(SIGTTOU)) == 0 &&
	    (ut->uu_sigmask & sigmask(SIGTTOU)) == 0) {
		pg = proc_pgrp(p);
		if (pg == PGRP_NULL) {
			error = EIO;
			goto out;
		}
		if (pg->pg_jobc == 0) {
			/* SAFE: All callers drop the lock on return */
			tty_unlock(tp);
			pg_rele(pg);
			tty_lock(tp);
			error = EIO;
			goto out;
		}
		/* SAFE: All callers drop the lock on return */
		tty_unlock(tp);
		pgsignal(pg, SIGTTOU, 1);
		pg_rele(pg);
		tty_lock(tp);
		/*
		 * We signalled ourself, so we need to act as if we
		 * have been "interrupted" from a "sleep" to act on
		 * the signal.  If it's a signal that stops the
		 * process, that's handled in the signal sending code.
		 */
		error = EINTR;
		goto out;
	}
	/*
	 * Process the user's data in at most OBUFSIZ chunks.  Perform any
	 * output translation.  Keep track of high water mark, sleep on
	 * overflow awaiting device aid in acquiring new space.
	 */
	while (uio_resid(uio) > 0 || cc > 0) {
		if (ISSET(tp->t_lflag, FLUSHO)) {
			uio_setresid(uio, 0);
			return 0;
		}
		if (tp->t_outq.c_cc > hiwat) {
			goto ovhiwat;
		}
		/*
		 * Grab a hunk of data from the user, unless we have some
		 * leftover from last time.
		 */
		if (cc == 0) {
			ssize_t size = uio_resid(uio);
			if (size < 0) {
				error = ERANGE;
				break;
			}
			cc = (int)MIN((size_t)size, OBUFSIZ);
			cp = obuf;
			error = uiomove(cp, cc, uio);
			if (error) {
				cc = 0;
				break;
			}
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
			if (!ISSET(tp->t_oflag, OPOST)) {
				ce = cc;
			} else {
				ce = (int)((size_t)cc - scanc((size_t)cc,
				    (u_char *)cp, char_type, CCLASSMASK));
				/*
				 * If ce is zero, then we're processing
				 * a special character through ttyoutput.
				 */
				if (ce == 0) {
					tp->t_rocount = 0;
					if (ttyoutput(*cp, tp) >= 0) {
						/* out of space */
						goto overfull;
					}
					cp++;
					cc--;
					if (ISSET(tp->t_lflag, FLUSHO) ||
					    tp->t_outq.c_cc > hiwat) {
						goto ovhiwat;
					}
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
			i = b_to_q((u_char *)cp, ce, &tp->t_outq);
			ce -= i;
			tp->t_column += ce;
			cp += ce;
			cc -= ce;
			tk_nout += ce;
			tp->t_outcc += ce;
			if (i > 0) {
				/* out of space */
				goto overfull;
			}
			if (ISSET(tp->t_lflag, FLUSHO) ||
			    tp->t_outq.c_cc > hiwat) {
				break;
			}
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
	return error;

overfull:

	/*
	 * Since we are using ring buffers, if we can't insert any more into
	 * the output queue, we can assume the ring is full and that someone
	 * forgot to set the high water mark correctly.  We set it and then
	 * proceed as normal.
	 */
	hiwat = tp->t_outq.c_cc - 1;

ovhiwat:
	ttstart(tp);
	/*
	 * This can only occur if FLUSHO is set in t_lflag,
	 * or if ttstart/oproc is synchronous (or very fast).
	 */
	if (tp->t_outq.c_cc <= hiwat) {
		goto loop;
	}
	if (flag & IO_NDELAY) {
		uio_setresid(uio, (uio_resid(uio) + cc));
		return uio_resid(uio) == count ? EWOULDBLOCK : 0;
	}
	SET(tp->t_state, TS_SO_OLOWAT);
	error = ttysleep(tp, TSA_OLOWAT(tp), TTOPRI | PCATCH, "ttywri",
	    tp->t_timeout);
	if (error == EWOULDBLOCK) {
		error = EIO;
	}
	if (error) {
		goto out;
	}
	goto loop;
}


/*
 * Rubout one character from the rawq of tp
 * as cleanly as possible.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
static void
ttyrub(int c, struct tty *tp)
{
	u_char *cp;
	int savecol;
	int tabc;

	TTY_LOCK_OWNED(tp);     /* debug assert */

	if (!ISSET(tp->t_lflag, ECHO) || ISSET(tp->t_lflag, EXTPROC)) {
		return;
	}
	CLR(tp->t_lflag, FLUSHO);
	if (ISSET(tp->t_lflag, ECHOE)) {
		if (tp->t_rocount == 0) {
			/*
			 * Messed up by ttwrite; retype
			 */
			ttyretype(tp);
			return;
		}
		if (c == ('\t' | TTY_QUOTE) || c == ('\n' | TTY_QUOTE)) {
			ttyrubo(tp, 2);
		} else {
			CLR(c, ~TTY_CHARMASK);
			switch (CCLASS(c)) {
			case ORDINARY:
				if (!(ISSET(tp->t_iflag, IUTF8) && CCONT(c))) {
					ttyrubo(tp, 1);
				}
				break;
			case BACKSPACE:
			case CONTROL:
			case NEWLINE:
			case RETURN:
			case VTAB:
				if (ISSET(tp->t_lflag, ECHOCTL)) {
					ttyrubo(tp, 2);
				}
				break;
			case TAB:
				if (tp->t_rocount < tp->t_rawq.c_cc) {
					ttyretype(tp);
					return;
				}
				savecol = tp->t_column;
				SET(tp->t_state, TS_CNTTB);
				SET(tp->t_lflag, FLUSHO);
				tp->t_column = tp->t_rocol;
				for (cp = firstc(&tp->t_rawq, &tabc); cp;
				    cp = nextc(&tp->t_rawq, cp, &tabc)) {
					ttyecho(tabc, tp);
				}
				CLR(tp->t_lflag, FLUSHO);
				CLR(tp->t_state, TS_CNTTB);

				/* savecol will now be length of the tab. */
				savecol -= tp->t_column;
				tp->t_column += savecol;
				if (savecol > 8) {
					savecol = 8;    /* overflow fixup */
				}
				while (--savecol >= 0) {
					(void)ttyoutput('\b', tp);
				}
				break;
			default:                        /* XXX */
#define PANICSTR        "ttyrub: would panic c = %d, val = %d\n"
				printf(PANICSTR, c, CCLASS(c));
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
	} else {
		ttyecho(tp->t_cc[VERASE], tp);
	}
	--tp->t_rocount;
}


/*
 * Back over count characters, erasing them.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
static void
ttyrubo(struct tty *tp, int count)
{
	TTY_LOCK_OWNED(tp);     /* debug assert */

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
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
static void
ttyretype(struct tty *tp)
{
	u_char *cp;
	int c;

	TTY_LOCK_OWNED(tp);     /* debug assert */

	/* Echo the reprint character. */
	if (tp->t_cc[VREPRINT] != _POSIX_VDISABLE) {
		ttyecho(tp->t_cc[VREPRINT], tp);
	}

	(void)ttyoutput('\n', tp);

	/*
	 * FREEBSD XXX
	 * FIX: NEXTC IS BROKEN - DOESN'T CHECK QUOTE
	 * BIT OF FIRST CHAR.
	 */
	for (cp = firstc(&tp->t_canq, &c); cp; cp = nextc(&tp->t_canq, cp, &c)) {
		ttyecho(c, tp);
	}
	for (cp = firstc(&tp->t_rawq, &c); cp; cp = nextc(&tp->t_rawq, cp, &c)) {
		ttyecho(c, tp);
	}
	CLR(tp->t_state, TS_ERASE);

	tp->t_rocount = tp->t_rawq.c_cc;
	tp->t_rocol = 0;
}


/*
 * Echo a typed character to the terminal.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
static void
ttyecho(int c, struct tty *tp)
{
	TTY_LOCK_OWNED(tp);     /* debug assert */

	if (!ISSET(tp->t_state, TS_CNTTB)) {
		CLR(tp->t_lflag, FLUSHO);
	}
	if ((!ISSET(tp->t_lflag, ECHO) &&
	    (c != '\n' || !ISSET(tp->t_lflag, ECHONL))) ||
	    ISSET(tp->t_lflag, EXTPROC)) {
		return;
	}
	if (ISSET(tp->t_lflag, ECHOCTL) &&
	    ((ISSET(c, TTY_CHARMASK) <= 037 && c != '\t' && c != '\n') ||
	    ISSET(c, TTY_CHARMASK) == 0177)) {
		(void)ttyoutput('^', tp);
		CLR(c, ~TTY_CHARMASK);
		if (c == 0177) {
			c = '?';
		} else {
			c += 'A' - 1;
		}
	}
	(void)ttyoutput(c, tp);
}

static void
ttwakeup_knote(struct selinfo *sip, long hint)
{
	if ((sip->si_flags & SI_KNPOSTING) == 0) {
		sip->si_flags |= SI_KNPOSTING;
		KNOTE(&sip->si_note, hint);
		sip->si_flags &= ~SI_KNPOSTING;
	}
}


/*
 * Wake up any readers on a tty.
 *
 * Locks:	Assumes tty_lock() is held for the call.
 */
void
ttwakeup(struct tty *tp)
{
	TTY_LOCK_OWNED(tp);     /* debug assert */

	selwakeup(&tp->t_rsel);
	ttwakeup_knote(&tp->t_rsel, 0);
	if (ISSET(tp->t_state, TS_ASYNC)) {
		/*
		 * XXX: Callers may not revalidate it the tty is closed
		 * XXX: out from under them by another thread, but we do
		 * XXX: not support queued signals.  This should be safe,
		 * XXX: since the process we intend to wakeup is in the
		 * XXX: process group, and will wake up because of the
		 * XXX: signal anyway.
		 */
		tty_unlock(tp);
		tty_pgsignal(tp, SIGIO, 1);
		tty_lock(tp);
	}
	wakeup(TSA_HUP_OR_INPUT(tp));
}


/*
 * ttwwakeup (LDISC)
 *
 * Wake up any writers on a tty.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
void
ttwwakeup(struct tty *tp)
{
	TTY_LOCK_OWNED(tp);     /* debug assert */

	if (tp->t_outq.c_cc <= tp->t_lowat) {
		selwakeup(&tp->t_wsel);
		ttwakeup_knote(&tp->t_wsel, 0);
	}
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
 *
 * Notes:	No locks are assumed for this function; it does not
 *		directly access struct tty.
 */
int
ttspeedtab(int speed, struct speedtab *table)
{
	for (; table->sp_speed != -1; table++) {
		if (table->sp_speed == speed) {
			return table->sp_code;
		}
	}
	return -1;
}


/*
 * Set tty hi and low water marks.
 *
 * Try to arrange the dynamics so there's about one second
 * from hi to low water.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
void
ttsetwater(struct tty *tp)
{
	speed_t cps;
	unsigned int x;

	TTY_LOCK_OWNED(tp);     /* debug assert */

#define CLAMP(x, h, l)  ((x) > h ? h : ((x) < l) ? l : (x))

	cps = tp->t_ospeed / 10;
	static_assert(TTMAXLOWAT <= UINT_MAX, "max low water fits in unsigned int");
	static_assert(TTMINLOWAT <= UINT_MAX, "min low water fits in unsigned int");
	tp->t_lowat = x = (unsigned int)CLAMP(cps / 2, TTMAXLOWAT, TTMINLOWAT);
	x += cps;
	x = CLAMP(x, TTMAXHIWAT, TTMINHIWAT);
	tp->t_hiwat = roundup(x, CBSIZE);
#undef  CLAMP
}

/* ttyinfo has been converted to the MACH kernel */
#include <mach/thread_info.h>

/* XXX Should be in Mach header <kern/thread.h>, but doesn't work */
extern kern_return_t    thread_info_internal(thread_t thread,
    thread_flavor_t flavor,
    thread_info_t thread_info_out,
    mach_msg_type_number_t *thread_info_count);


/*
 * Report on state of foreground process group.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
void
ttyinfo_locked(struct tty *tp)
{
	int             load;
	thread_t        thread;
	uthread_t       uthread;
	proc_t          p;
	proc_t          pick;
	pid_t pickpid;
	const char      *state;
	struct timeval  utime;
	struct timeval  stime;
	thread_basic_info_data_t        basic_info;
	mach_msg_type_number_t          mmtn = THREAD_BASIC_INFO_COUNT;
	struct pgrp * pg;

	TTY_LOCK_OWNED(tp);     /* debug assert */

	if (ttycheckoutq(tp, 0) == 0) {
		return;
	}

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
	/* XXX is there a need for pgrp lock ? */
	if ((p = tp->t_pgrp->pg_members.lh_first) == NULL) {
		ttyprintf(tp, "empty foreground process group\n");
		tp->t_rocount = 0;
		return;
	}

	/*
	 * Pick the most interesting process and copy some of its
	 * state for printing later.
	 */
	pg = proc_pgrp(p);
	pgrp_lock(pg);
	/* the proc_compare is non blocking fn, no need to use iterator */
	for (pick = NULL; p != NULL; p = p->p_pglist.le_next) {
		if (proc_compare(pick, p)) {
			pick = p;
			pickpid = p->p_pid;
		} else {
			pickpid = pick->p_pid;
		}
	}
	pgrp_unlock(pg);
	/* SAFE: All callers drop the lock on return */
	tty_unlock(tp);
	pg_rele(pg);
	tty_lock(tp);

	pick = proc_find(pickpid);
	if (pick == PROC_NULL) {
		return;
	}

	if (TAILQ_EMPTY(&pick->p_uthlist) ||
	    (uthread = TAILQ_FIRST(&pick->p_uthlist)) == NULL ||
	    (thread = vfs_context_thread(&uthread->uu_context)) == NULL ||
	    (thread_info_internal(thread, THREAD_BASIC_INFO, (thread_info_t)&basic_info, &mmtn) != KERN_SUCCESS)) {
		ttyprintf(tp, "foreground process without thread\n");
		tp->t_rocount = 0;
		proc_rele(pick);
		return;
	}

	switch (basic_info.run_state) {
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
	ttyprintf(tp, " cmd: %s %d %s %ld.%02du %ld.%02ds\n",
	    pick->p_comm,
	    pick->p_pid,
	    state,
	    (long)utime.tv_sec, utime.tv_usec / 10000,
	    (long)stime.tv_sec, stime.tv_usec / 10000);

	proc_rele(pick);
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
#define ISRUN(p)        (((p)->p_stat == SRUN) || ((p)->p_stat == SIDL))
#define TESTAB(a, b)    ((a)<<1 | (b))
#define ONLYA   2
#define ONLYB   1
#define BOTH    3

/*
 * Locks:	pgrp_lock(p2) held on call to this function
 *		tty_lock(tp) for p2's tty, for which p2 is the foreground
 *			process, held on call to this function
 */
static int
proc_compare(proc_t p1, proc_t p2)
{
	/* NOTE THIS FN needs to be NON BLOCKING */

	if (p1 == NULL) {
		return 1;
	}
	/*
	 * see if at least one of them is runnable
	 */
	switch (TESTAB(ISRUN(p1), ISRUN(p2))) {
	case ONLYA:
		return 0;
	case ONLYB:
		return 1;
	case BOTH:
		/*
		 * tie - favor one with highest recent cpu utilization
		 */
#ifdef _PROC_HAS_SCHEDINFO_
		/* Without the support the fields are always zero */
		if (p2->p_estcpu > p1->p_estcpu) {
			return 1;
		}
		if (p1->p_estcpu > p2->p_estcpu) {
			return 0;
		}
#endif /* _PROC_HAS_SCHEDINFO_ */
		return p2->p_pid > p1->p_pid; /* tie - return highest pid */
	}
	/*
	 * weed out zombies
	 */
	switch (TESTAB(p1->p_stat == SZOMB, p2->p_stat == SZOMB)) {
	case ONLYA:
		return 1;
	case ONLYB:
		return 0;
	case BOTH:
		return p2->p_pid > p1->p_pid; /* tie - return highest pid */
	}
	/*
	 * pick the one with the smallest sleep time
	 */
#ifdef _PROC_HAS_SCHEDINFO_
	/* Without the support the fields are always zero */
	if (p2->p_slptime > p1->p_slptime) {
		return 0;
	}
	if (p1->p_slptime > p2->p_slptime) {
		return 1;
	}
#endif /* _PROC_HAS_SCHEDINFO_ */
	return p2->p_pid > p1->p_pid;         /* tie - return highest pid */
}


/*
 * Output char to tty; console putchar style.
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 *
 * Notes:	Only ever called from putchar() in subr_prf.c
 */
int
tputchar(int c, struct tty *tp)
{
	TTY_LOCK_OWNED(tp);     /* debug assert */

	if (!ISSET(tp->t_state, TS_CONNECTED)) {
		return -1;
	}
	if (c == '\n') {
		(void)ttyoutput('\r', tp);
	}
	(void)ttyoutput(c, tp);
	ttstart(tp);
	return 0;
}


/*
 * ttysleep
 *
 * Sleep on a wait channel waiting for an interrupt or a condition to come
 * true so that we are woken up.
 *
 * Parameters:	tp			Tty going to sleep
 *		chan			The sleep channel (usually an address
 *					of a structure member)
 *		pri			priority and flags
 *		wmesg			Wait message; shows up in debugger,
 *					should show up in "ps", but doesn't
 *		timo			Timeout for the sleep
 *
 * Returns:	0			Condition came true
 *		ERESTART		Upper layer must redrive the call;
 *					this is usually done by the Libc
 *					stub in user space
 *	msleep0:EINTR			Interrupted (usually a signal)
 *	msleep0:ERESTART		Interrupted (usually a masked signal)
 *	msleep0:EWOULDBLOCK		Timeout (timo) already expired
 *
 * Locks:	Assumes tty_lock() is held prior to calling.
 *
 * Sleep on chan, returning ERESTART if tty changed while we napped and
 * returning any errors (e.g. EINTR/EWOULDBLOCK) reported by msleep0.  If
 * the tty is revoked, restarting a pending call will redo validation done
 * at the start of the call.
 */
int
ttysleep(struct tty *tp, void *chan, int pri, const char *wmesg, int timo)
{
	int error;
	int gen;

	TTY_LOCK_OWNED(tp);

	if (tp->t_state & TS_REVOKE) {
		return ERESTART;
	}

	gen = tp->t_gen;
	/* Use of msleep0() avoids conversion timo/timespec/timo */
	error = msleep0(chan, &tp->t_lock, pri, wmesg, timo, (int (*)(int))0);
	if (error) {
		return error;
	}
	return tp->t_gen == gen ? 0 : ERESTART;
}


/*
 * Allocate a tty structure and its associated buffers.
 *
 * Parameters:	void
 *
 * Returns:	!NULL				Address of new struct tty
 *		NULL				Error ("ENOMEM")
 *
 * Locks:	The tty_lock() of the returned tty is not held when it
 *		is returned.
 */
struct tty *
ttymalloc(void)
{
	struct tty *tp;

	MALLOC(tp, struct tty *, sizeof(struct tty), M_TTYS, M_WAITOK | M_ZERO);
	if (tp != NULL) {
		/* XXX: default to TTYCLSIZE(1024) chars for now */
		clalloc(&tp->t_rawq, TTYCLSIZE, 1);
		clalloc(&tp->t_canq, TTYCLSIZE, 1);
		/* output queue doesn't need quoting */
		clalloc(&tp->t_outq, TTYCLSIZE, 0);
		lck_mtx_init(&tp->t_lock, tty_lck_grp, tty_lck_attr);
		klist_init(&tp->t_rsel.si_note);
		klist_init(&tp->t_wsel.si_note);
		tp->t_refcnt = 1;
	}
	return tp;
}

/*
 * Increment the reference count on a tty.
 */
void
ttyhold(struct tty *tp)
{
	TTY_LOCK_OWNED(tp);
	tp->t_refcnt++;
}

/*
 * Drops a reference count on a tty structure; if the reference count reaches
 * zero, then also frees the structure and associated buffers.
 */
void
ttyfree(struct tty *tp)
{
	TTY_LOCK_NOTOWNED(tp);

	tty_lock(tp);
	if (--tp->t_refcnt == 0) {
		tty_unlock(tp);
		ttydeallocate(tp);
	} else if (tp->t_refcnt < 0) {
		panic("%s: freeing free tty %p", __func__, tp);
	} else {
		tty_unlock(tp);
	}
}

/*
 * Deallocate a tty structure and its buffers.
 *
 * Locks:	The tty_lock() is assumed to not be held at the time of
 *		the free; this function destroys the mutex.
 */
static void
ttydeallocate(struct tty *tp)
{
	TTY_LOCK_NOTOWNED(tp);  /* debug assert */

#if DEBUG
	if (!(SLIST_EMPTY(&tp->t_rsel.si_note) && SLIST_EMPTY(&tp->t_wsel.si_note))) {
		panic("knotes hooked into a tty when the tty is freed.\n");
	}
#endif /* DEBUG */

	clfree(&tp->t_rawq);
	clfree(&tp->t_canq);
	clfree(&tp->t_outq);
	lck_mtx_destroy(&tp->t_lock, tty_lck_grp);
	FREE(tp, M_TTYS);
}


/*
 * Locks:	Assumes tty_lock() is held prior to calling.
 */
int
isbackground(proc_t p, struct tty  *tp)
{
	TTY_LOCK_OWNED(tp);

	return tp->t_session != NULL && p->p_pgrp != NULL && (p->p_pgrp != tp->t_pgrp) && isctty_sp(p, tp, p->p_pgrp->pg_session);
}

static int
isctty(proc_t p, struct tty  *tp)
{
	int retval;
	struct session * sessp;

	sessp = proc_session(p);
	retval = (sessp == tp->t_session && p->p_flag & P_CONTROLT);
	session_rele(sessp);
	return retval;
}

static int
isctty_sp(proc_t p, struct tty  *tp, struct session *sessp)
{
	return sessp == tp->t_session && p->p_flag & P_CONTROLT;
}


static int  filt_ttyattach(struct knote *kn, struct kevent_qos_s *kev);
static void filt_ttydetach(struct knote *kn);
static int  filt_ttyevent(struct knote *kn, long hint);
static int  filt_ttytouch(struct knote *kn, struct kevent_qos_s *kev);
static int  filt_ttyprocess(struct knote *kn, struct kevent_qos_s *kev);

SECURITY_READ_ONLY_EARLY(struct filterops) tty_filtops = {
	.f_isfd    = 1,
	.f_attach  = filt_ttyattach,
	.f_detach  = filt_ttydetach,
	.f_event   = filt_ttyevent,
	.f_touch   = filt_ttytouch,
	.f_process = filt_ttyprocess
};

/*
 * Called with struct tty locked. Returns non-zero if there is data to be read
 * or written.
 */
static int
filt_tty_common(struct knote *kn, struct kevent_qos_s *kev, struct tty *tp)
{
	int retval = 0;
	int64_t data = 0;

	TTY_LOCK_OWNED(tp); /* debug assert */

	switch (kn->kn_filter) {
	case EVFILT_READ:
		/*
		 * ttnread can change the tty state,
		 * hence must be done upfront, before any other check.
		 */
		data = ttnread(tp);
		retval = (data != 0);
		break;
	case EVFILT_WRITE:
		if ((tp->t_outq.c_cc <= tp->t_lowat) &&
		    (tp->t_state & TS_CONNECTED)) {
			data = tp->t_hiwat - tp->t_outq.c_cc;
			retval = (data != 0);
		}
		break;
	default:
		panic("tty kevent: unexpected filter: %d, kn = %p, tty = %p",
		    kn->kn_filter, kn, tp);
		break;
	}

	/*
	 * TODO(mwidmann, jandrus): For native knote low watermark support,
	 * check the kn_sfflags for NOTE_LOWAT and check against kn_sdata.
	 *
	 * res = ((kn->kn_sfflags & NOTE_LOWAT) != 0) ?
	 *        (kn->kn_data >= kn->kn_sdata) : kn->kn_data;
	 */

	if (tp->t_state & TS_ZOMBIE) {
		kn->kn_flags |= EV_EOF;
	}
	if (kn->kn_flags & EV_EOF) {
		retval = 1;
	}
	if (retval && kev) {
		knote_fill_kevent(kn, kev, data);
	}

	return retval;
}

/*
 * Find the struct tty from a waitq, which is a member of one of the two struct
 * selinfos inside the struct tty.  Use the seltype to determine which selinfo.
 */
static struct tty *
tty_from_waitq(struct waitq *wq, int seltype)
{
	struct selinfo *si;
	struct tty *tp = NULL;

	/*
	 * The waitq is part of the selinfo structure managed by the driver. For
	 * certain drivers, we want to hook the knote into the selinfo
	 * structure's si_note field so selwakeup can call KNOTE.
	 *
	 * While 'wq' is not really a queue element, this macro only uses the
	 * pointer to calculate the offset into a structure given an element
	 * name.
	 */
	si = qe_element(wq, struct selinfo, si_waitq);

	/*
	 * For TTY drivers, the selinfo structure is somewhere in the struct
	 * tty. There are two different selinfo structures, and the one used
	 * corresponds to the type of filter requested.
	 *
	 * While 'si' is not really a queue element, this macro only uses the
	 * pointer to calculate the offset into a structure given an element
	 * name.
	 */
	switch (seltype) {
	case FREAD:
		tp = qe_element(si, struct tty, t_rsel);
		break;
	case FWRITE:
		tp = qe_element(si, struct tty, t_wsel);
		break;
	}

	return tp;
}

static struct tty *
tty_from_knote(struct knote *kn)
{
	return (struct tty *)kn->kn_hook;
}

/*
 * Set the knote's struct tty to the kn_hook field.
 *
 * The idea is to fake a call to select with our own waitq set.  If the driver
 * calls selrecord, we'll get a link to their waitq and access to the tty
 * structure.
 *
 * Returns -1 on failure, with the error set in the knote, or selres on success.
 */
static int
tty_set_knote_hook(struct knote *kn)
{
	uthread_t uth;
	vfs_context_t ctx;
	vnode_t vp;
	kern_return_t kr;
	struct waitq *wq = NULL;
	struct waitq_set *old_wqs;
	struct waitq_set tmp_wqs;
	uint64_t rsvd, rsvd_arg;
	uint64_t *rlptr = NULL;
	int selres = -1;
	struct tty *tp;

	uth = get_bsdthread_info(current_thread());

	ctx = vfs_context_current();
	vp = (vnode_t)kn->kn_fp->fp_glob->fg_data;

	/*
	 * Reserve a link element to avoid potential allocation under
	 * a spinlock.
	 */
	rsvd = rsvd_arg = waitq_link_reserve(NULL);
	rlptr = (void *)&rsvd_arg;

	/*
	 * Trick selrecord into hooking a known waitq set into the device's selinfo
	 * waitq.  Once the link is in place, we can get back into the selinfo from
	 * the waitq and subsequently the tty (see tty_from_waitq).
	 *
	 * We can't use a real waitq set (such as the kqueue's) because wakeups
	 * might happen before we can unlink it.
	 */
	kr = waitq_set_init(&tmp_wqs, SYNC_POLICY_FIFO | SYNC_POLICY_PREPOST, NULL,
	    NULL);
	assert(kr == KERN_SUCCESS);

	/*
	 * Lazy allocate the waitqset to avoid potential allocation under
	 * a spinlock;
	 */
	waitq_set_lazy_init_link(&tmp_wqs);

	old_wqs = uth->uu_wqset;
	uth->uu_wqset = &tmp_wqs;
	/*
	 * FMARK forces selects to always call selrecord, even if data is
	 * available.  See ttselect, ptsselect, ptcselect.
	 *
	 * selres also contains the data currently available in the tty.
	 */
	selres = VNOP_SELECT(vp, knote_get_seltype(kn) | FMARK, 0, rlptr, ctx);
	uth->uu_wqset = old_wqs;

	/*
	 * Make sure to cleanup the reserved link - this guards against
	 * drivers that may not actually call selrecord().
	 */
	waitq_link_release(rsvd);
	if (rsvd == rsvd_arg) {
		/*
		 * The driver didn't call selrecord -- there's no tty hooked up so we
		 * can't attach.
		 */
		knote_set_error(kn, ENOTTY);
		selres = -1;
		goto out;
	}

	/* rlptr may not point to a properly aligned pointer */
	memcpy(&wq, rlptr, sizeof(void *));

	tp = tty_from_waitq(wq, knote_get_seltype(kn));
	assert(tp != NULL);

	/*
	 * Take a reference and stash the tty in the knote.
	 */
	tty_lock(tp);
	ttyhold(tp);
	kn->kn_hook = tp;
	tty_unlock(tp);

out:
	/*
	 * Cleaning up the wqset will unlink its waitq and clean up any preposts
	 * that occurred as a result of data coming in while the tty was attached.
	 */
	waitq_set_deinit(&tmp_wqs);

	return selres;
}

static int
filt_ttyattach(struct knote *kn, __unused struct kevent_qos_s *kev)
{
	int selres = 0;
	struct tty *tp;

	/*
	 * This function should be called from filt_specattach (spec_vnops.c),
	 * so most of the knote data structure should already be initialized.
	 */

	/* don't support offsets in ttys or drivers that don't use struct tty */
	if (kn->kn_vnode_use_ofst || !kn->kn_vnode_kqok) {
		knote_set_error(kn, ENOTSUP);
		return 0;
	}

	/*
	 * Connect the struct tty to the knote through the selinfo structure
	 * referenced by the waitq within the selinfo.
	 */
	selres = tty_set_knote_hook(kn);
	if (selres < 0) {
		return 0;
	}

	/*
	 * Attach the knote to selinfo's klist.
	 */
	tp = tty_from_knote(kn);
	tty_lock(tp);

	switch (kn->kn_filter) {
	case EVFILT_READ:
		KNOTE_ATTACH(&tp->t_rsel.si_note, kn);
		break;
	case EVFILT_WRITE:
		KNOTE_ATTACH(&tp->t_wsel.si_note, kn);
		break;
	default:
		panic("invalid knote %p attach, filter: %d", kn, kn->kn_filter);
	}

	tty_unlock(tp);

	return selres;
}

static void
filt_ttydetach(struct knote *kn)
{
	struct tty *tp = tty_from_knote(kn);

	tty_lock(tp);

	switch (kn->kn_filter) {
	case EVFILT_READ:
		KNOTE_DETACH(&tp->t_rsel.si_note, kn);
		break;
	case EVFILT_WRITE:
		KNOTE_DETACH(&tp->t_wsel.si_note, kn);
		break;
	default:
		panic("invalid knote %p detach, filter: %d", kn, kn->kn_filter);
		break;
	}

	tty_unlock(tp);
	ttyfree(tp);
}

static int
filt_ttyevent(struct knote *kn, long hint)
{
	struct tty *tp = tty_from_knote(kn);
	int ret;

	TTY_LOCK_OWNED(tp);

	if (hint & NOTE_REVOKE) {
		kn->kn_flags |= EV_EOF | EV_ONESHOT;
		ret = 1;
	} else {
		ret = filt_tty_common(kn, NULL, tp);
	}

	return ret;
}

static int
filt_ttytouch(struct knote *kn, struct kevent_qos_s *kev)
{
	struct tty *tp = tty_from_knote(kn);
	int res = 0;

	tty_lock(tp);

	kn->kn_sdata = kev->data;
	kn->kn_sfflags = kev->fflags;

	if (kn->kn_vnode_kqok) {
		res = filt_tty_common(kn, NULL, tp);
	}

	tty_unlock(tp);

	return res;
}

static int
filt_ttyprocess(struct knote *kn, struct kevent_qos_s *kev)
{
	struct tty *tp = tty_from_knote(kn);
	int res;

	tty_lock(tp);

	res = filt_tty_common(kn, kev, tp);

	tty_unlock(tp);

	return res;
}
