/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1986, 1988, 1991, 1993
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
 *	@(#)subr_prf.c	8.4 (Berkeley) 5/4/95
 */
/* HISTORY
 * 22-Sep-1997 Umesh Vaishampayan (umeshv@apple.com)
 *	Cleaned up m68k crud. Fixed vlog() to do logpri() for ppc, too.
 *
 * 17-July-97  Umesh Vaishampayan (umeshv@apple.com)
 *	Eliminated multiple definition of constty which is defined
 *	in bsd/dev/XXX/cons.c
 *
 * 26-MAR-1997 Umesh Vaishampayan (umeshv@NeXT.com
 * 	Fixed tharshing format in many functions. Cleanup.
 * 
 * 17-Jun-1995 Mac Gillon (mgillon) at NeXT
 *	Purged old history
 *	New version based on 4.4 and NS3.3
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/reboot.h>
#include <sys/msgbuf.h>
#include <sys/proc_internal.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/file_internal.h>
#include <sys/tprintf.h>
#include <sys/syslog.h>
#include <stdarg.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/subr_prf.h>

#include <kern/cpu_number.h>	/* for cpu_number() */
#include <machine/spl.h>
#include <libkern/libkern.h>

/* for vaddlog(): the following are implemented in osfmk/kern/printf.c  */
extern void bsd_log_lock(void);
extern void bsd_log_unlock(void);

/* Keep this around only because it's exported */
void _printf(int, struct tty *, const char *, ...);

struct snprintf_arg {
	char *str;
	size_t remain;
};


/*
 * In case console is off,
 * panicstr contains argument to last
 * call to panic.
 */
extern const char	*panicstr;

extern	void cnputc(char);		/* standard console putc */
void	(*v_putc)(char) = cnputc;	/* routine to putc on virtual console */

extern	struct tty cons;		/* standard console tty */
extern struct	tty *constty;		/* pointer to console "window" tty */
extern int  __doprnt(const char *fmt,
					 va_list    argp,
					 void       (*)(int, void *),
					 void       *arg,
					 int        radix,
					 int        is_log);

/*
 *	Record cpu that panic'd and lock around panic data
 */
static void printn(uint32_t n, int b, int flags, struct tty *ttyp, int zf, int fld_size);

extern	void logwakeup(void);
extern	void halt_cpu(void);

static void
snprintf_func(int ch, void *arg);

struct putchar_args {
	int flags;
	struct tty *tty;
};
static void putchar(int c, void *arg);


/*
 * Uprintf prints to the controlling terminal for the current process.
 * It may block if the tty queue is overfull.  No message is printed if
 * the queue does not clear in a reasonable time.
 */
void
uprintf(const char *fmt, ...)
{
	struct proc *p = current_proc();
	struct putchar_args pca;
	va_list ap;
	struct session *sessp;
	
	sessp = proc_session(p);

	if (p->p_flag & P_CONTROLT && sessp != SESSION_NULL && sessp->s_ttyvp) {
		pca.flags = TOTTY;
		pca.tty   = SESSION_TP(sessp);
		if (pca.tty != NULL)
			tty_lock(pca.tty);
		va_start(ap, fmt);
		__doprnt(fmt, ap, putchar, &pca, 10, FALSE);
		va_end(ap);
		if (pca.tty != NULL)
		tty_unlock(pca.tty);
	}
	if (sessp != SESSION_NULL)
		session_rele(sessp);
}

tpr_t
tprintf_open(struct proc *p)
{
	struct session * sessp;

	sessp = proc_session(p);

	if (p->p_flag & P_CONTROLT && sessp->s_ttyvp) {
		return ((tpr_t)sessp);
	}
	if (sessp != SESSION_NULL)
		session_rele(sessp);

	return ((tpr_t) NULL);
}

void
tprintf_close(tpr_t sessp)
{
	if (sessp)
		session_rele((struct session *) sessp);
}

/*
 * tprintf prints on the controlling terminal associated
 * with the given session.
 *
 * NOTE:	No one else should call this function!!!
 */
void
tprintf(tpr_t tpr, const char *fmt, ...)
{
	struct session *sess = (struct session *)tpr;
	struct tty *tp = TTY_NULL;
	int flags = TOLOG;
	va_list ap;
	struct putchar_args pca;

	logpri(LOG_INFO);

	if (sess && (tp = SESSION_TP(sess)) != TTY_NULL) {
		/* ttycheckoutq(), tputchar() require a locked tp */
		tty_lock(tp);
		if(ttycheckoutq(tp, 0)) {
			flags |= TOTTY;
			/* going to the tty; leave locked */
		} else {
			/* not going to the tty... */
			tty_unlock(tp);
			tp = TTY_NULL;
		}
	}
	
	pca.flags = flags;
	pca.tty   = tp;
	va_start(ap, fmt);
	__doprnt(fmt, ap, putchar, &pca, 10, FALSE);
	va_end(ap);

	if (tp != NULL)
		tty_unlock(tp);	/* lock/unlock is guarded by tp, above */

	logwakeup();
}

/*
 * Ttyprintf displays a message on a tty; it should be used only by
 * the tty driver, or anything that knows the underlying tty will not
 * be revoke(2)'d away.  Other callers should use tprintf.
 *
 * Locks:	It is assumed that the tty_lock() is held over the call
 *		to this function.  Ensuring this is the responsibility
 *		of the caller.
 */
void
ttyprintf(struct tty *tp, const char *fmt, ...)
{
	va_list ap;

	if (tp != NULL) {
		struct putchar_args pca;
		pca.flags = TOTTY;
		pca.tty   = tp;
		
		va_start(ap, fmt);
		__doprnt(fmt, ap, putchar, &pca, 10, TRUE);
		va_end(ap);
	}
}


extern	int log_open;


void
logpri(int level)
{
	struct putchar_args pca;
	pca.flags = TOLOG;
	pca.tty   = NULL;
	
	putchar('<', &pca);
	printn((uint32_t)level, 10, TOLOG, (struct tty *)0, 0, 0);
	putchar('>', &pca);
}

static void
_logtime(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vaddlog(fmt, ap);
	va_end(ap);
}

void
logtime(time_t secs)
{
	_logtime("         0 [Time %ld] [Message ", secs);
}

int
vaddlog(const char *fmt, va_list ap)
{
	struct putchar_args pca;

	pca.flags = TOLOGLOCKED;
	pca.tty   = NULL;

	if (!log_open) {
		pca.flags |= TOCONS;
	}

	bsd_log_lock();
	__doprnt(fmt, ap, putchar, &pca, 10, TRUE);
	bsd_log_unlock();
	
	logwakeup();
	return 0;
}

void
_printf(int flags, struct tty *ttyp, const char *format, ...)
{
	va_list ap;
	struct putchar_args pca;

	pca.flags = flags;
	pca.tty   = ttyp;

	if (ttyp != NULL) {
		tty_lock(ttyp);
	
		va_start(ap, format);
		__doprnt(format, ap, putchar, &pca, 10, TRUE);
		va_end(ap);

		tty_unlock(ttyp);
	}
}

int
prf(const char *fmt, va_list ap, int flags, struct tty *ttyp)
{
	struct putchar_args pca;

	pca.flags = flags;
	pca.tty   = ttyp;

	__doprnt(fmt, ap, putchar, &pca, 10, TRUE);

	return 0;
}

/*
 * Printn prints a number n in base b.
 * We don't use recursion to avoid deep kernel stacks.
 */
static void
printn(uint32_t n, int b, int flags, struct tty *ttyp, int zf, int fld_size)
{
	char prbuf[11];
	char *cp;
	struct putchar_args pca;

	pca.flags = flags;
	pca.tty   = ttyp;

	if (b == 10 && (int)n < 0) {
		putchar('-', &pca);
		n = (unsigned)(-(int)n);
	}
	cp = prbuf;
	do {
		*cp++ = "0123456789abcdef"[n%b];
		n /= b;
	} while (n);
	if (fld_size) {
		for (fld_size -= cp - prbuf; fld_size > 0; fld_size--)
			if (zf)
				putchar('0', &pca);
			else
				putchar(' ', &pca);
	}
	do
		putchar(*--cp, &pca);
	while (cp > prbuf);
}



/*
 * Warn that a system table is full.
 */
void tablefull(const char *tab)
{
	log(LOG_ERR, "%s: table is full\n", tab);
}

/*
 * Print a character on console or users terminal.
 * If destination is console then the last MSGBUFS characters
 * are saved in msgbuf for inspection later.
 *
 * Locks:	If TOTTY is set, we assume that the tty lock is held
 *		over the call to this function.
 */
/*ARGSUSED*/
void
putchar(int c, void *arg)
{
	struct putchar_args *pca = arg;
	char **sp = (char**) pca->tty;

	if (panicstr)
		constty = 0;
	if ((pca->flags & TOCONS) && pca->tty == NULL && constty) {
		pca->tty = constty;
		pca->flags |= TOTTY;
	}
	if ((pca->flags & TOTTY) && pca->tty && tputchar(c, pca->tty) < 0 &&
	    (pca->flags & TOCONS) && pca->tty == constty)
		constty = 0;
	if ((pca->flags & TOLOG) && c != '\0' && c != '\r' && c != 0177)
		log_putc(c);
	if ((pca->flags & TOLOGLOCKED) && c != '\0' && c != '\r' && c != 0177)
		log_putc_locked(c);
	if ((pca->flags & TOCONS) && constty == 0 && c != '\0')
		(*v_putc)(c);
	if (pca->flags & TOSTR) {
		**sp = c;
		(*sp)++;
	}
}

int
vprintf(const char *fmt, va_list ap)
{
	struct putchar_args pca;

	pca.flags = TOLOG | TOCONS;
	pca.tty   = NULL;
	__doprnt(fmt, ap, putchar, &pca, 10, TRUE);
	return 0;
}


/*
 * Scaled down version of vsprintf(3).
 *
 * Deprecation Warning:
 *	vsprintf() is being deprecated. Please use vsnprintf() instead. 
 */
int
vsprintf(char *buf, const char *cfmt, va_list ap)
{
	int retval;
	struct snprintf_arg info;

	info.str = buf;
	info.remain = 999999;

	retval = __doprnt(cfmt, ap, snprintf_func, &info, 10, FALSE);
	if (info.remain >= 1) {
		*info.str++ = '\0';
	}
	return 0;
}

/*
 * Scaled down version of snprintf(3).
 */
int
snprintf(char *str, size_t size, const char *format, ...)
{
	int retval;
	va_list ap;

	va_start(ap, format);
	retval = vsnprintf(str, size, format, ap);
	va_end(ap);
	return(retval);
}

/*
 * Scaled down version of vsnprintf(3).
 */
int
vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
	struct snprintf_arg info;
	int retval;

	info.str = str;
	info.remain = size;
	retval = __doprnt(format, ap, snprintf_func, &info, 10, FALSE);
	if (info.remain >= 1)
		*info.str++ = '\0';
	return retval;
}

static void
snprintf_func(int ch, void *arg)
{
	struct snprintf_arg *const info = arg;

	if (info->remain >= 2) {
		*info->str++ = ch;
		info->remain--;
	}
}

int
kvprintf(char const *fmt, void (*func)(int, void*), void *arg, int radix, va_list ap)
{
	__doprnt(fmt, ap, func, arg, radix, TRUE);
	return 0;
}

