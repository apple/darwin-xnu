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
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/reboot.h>
#include <sys/msgbuf.h>
#include <sys/proc.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/file.h>
#include <sys/tprintf.h>
#include <sys/syslog.h>
#include <stdarg.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <kern/parallel.h>
#include <sys/subr_prf.h>

#include <kern/cpu_number.h>	/* for cpu_number() */
#include <machine/spl.h>
#include <libkern/libkern.h>

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

extern	cnputc();			/* standard console putc */
int	(*v_putc)() = cnputc;		/* routine to putc on virtual console */

extern	struct tty cons;		/* standard console tty */
extern struct	tty *constty;		/* pointer to console "window" tty */

/*
 *	Record cpu that panic'd and lock around panic data
 */

static void puts(const char *s, int flags, struct tty *ttyp);
static void printn(u_long n, int b, int flags, struct tty *ttyp, int zf, int fld_size);

/* MP printf stuff */
decl_simple_lock_data(,printf_lock)
#if	NCPUS > 1
boolean_t new_printf_cpu_number;  /* do we need to output who we are */
#endif

extern	void logwakeup();
extern	void halt_cpu();
extern	boot();
int	putchar();

static void
snprintf_func(int ch, void *arg);



/*
 * Uprintf prints to the controlling terminal for the current process.
 * It may block if the tty queue is overfull.  No message is printed if
 * the queue does not clear in a reasonable time.
 */
void
uprintf(const char *fmt, ...)
{
	register struct proc *p = current_proc();
	va_list ap;

	unix_master();		/* sessions, sigh */
	if (p->p_flag & P_CONTROLT && p->p_session->s_ttyvp) {
		va_start(ap, fmt);
		prf(fmt, ap, TOTTY, (struct tty *)p->p_session->s_ttyvp);
		va_end(ap);
	}
	unix_release();
}

tpr_t
tprintf_open(p)
	register struct proc *p;
{
	unix_master();		/* sessions, sigh */
	if (p->p_flag & P_CONTROLT && p->p_session->s_ttyvp) {
		SESSHOLD(p->p_session);
		unix_release();
		return ((tpr_t) p->p_session);
	}
	unix_release();
	return ((tpr_t) NULL);
}

void
tprintf_close(sess)
	tpr_t sess;
{
	unix_master();		/* sessions, sigh */
	if (sess)
		SESSRELE((struct session *) sess);
	unix_release();
}

/*
 * tprintf prints on the controlling terminal associated
 * with the given session.
 */
void
tprintf(tpr_t tpr, const char *fmt, ...)
{
	register struct session *sess = (struct session *)tpr;
	struct tty *tp = NULL;
	int flags = TOLOG;
	va_list ap;

	logpri(LOG_INFO);
	unix_master();		/* sessions, sigh */
	if (sess && sess->s_ttyvp && ttycheckoutq(sess->s_ttyp, 0)) {
		flags |= TOTTY;
		tp = sess->s_ttyp;
	}
	if (tp != NULL) {
		va_start(ap, fmt);
		prf(fmt, ap, TOTTY, tp);
		va_end(ap);
	}
	unix_release();
	logwakeup();
}

/*
 * Ttyprintf displays a message on a tty; it should be used only by
 * the tty driver, or anything that knows the underlying tty will not
 * be revoke(2)'d away.  Other callers should use tprintf.
 */
void
ttyprintf(struct tty *tp, const char *fmt, ...)
{
	va_list ap;

	if (tp != NULL) {
		va_start(ap, fmt);
		prf(fmt, ap, TOTTY, tp);
		va_end(ap);
	}
}

extern	int log_open;


void
logpri(level)
	int level;
{

	putchar('<', TOLOG, (struct tty *)0);
	printn((u_long)level, 10, TOLOG, (struct tty *)0, 0, 0);
	putchar('>', TOLOG, (struct tty *)0);
}

void
addlog(const char *fmt, ...)
{
	register s = splhigh();
	va_list ap;

	va_start(ap, fmt);
	prf(fmt, ap, TOLOG, (struct tty *)0);
	splx(s);
	if (!log_open)
		prf(fmt, ap, TOCONS, (struct tty *)0);
	va_end(ap);
	logwakeup();
}
void _printf(int flags, struct tty *ttyp, const char *format, ...)
{
	va_list ap;
	
	va_start(ap, format);
	prf(format, ap, flags, ttyp);
	va_end(ap);
}

int prf(const char *fmt, va_list ap, int flags, struct tty *ttyp)
{
	register int b, c, i;
	char *s;
	int any;
	int zf = 0, fld_size;
	
#if	NCPUS > 1
	int cpun = cpu_number();

	if(ttyp == 0) {
		simple_lock(&printf_lock);
	} else
		TTY_LOCK(ttyp);
		
	if (cpun != master_cpu)
		new_printf_cpu_number = TRUE;

	if (new_printf_cpu_number) {
		putchar('{', flags, ttyp);
		printn((u_long)cpun, 10, flags, ttyp, 0, 0);
		putchar('}', flags, ttyp);
	}
#endif	/* NCPUS > 1 */	
loop:
	while ((c = *fmt++) != '%') {
		if (c == '\0') {
#if	NCPUS > 1
			if(ttyp == 0) {
				simple_unlock(&printf_lock);
			} else
				TTY_UNLOCK(ttyp);
#endif
			return 0;
		}
		putchar(c, flags, ttyp);
	}
again:
	zf = 0;
	fld_size = 0;
	c = *fmt++;
	if (c == '0')
		zf = '0';
	fld_size = 0;
	for (;c <= '9' && c >= '0'; c = *fmt++)
		fld_size = fld_size * 10 + c - '0';
	
	/* THIS CODE IS VAX DEPENDENT IN HANDLING %l? AND %c */
	switch (c) {

	case 'l':
		goto again;
	case 'x': case 'X':
		b = 16;
		goto number;
	case 'd': case 'D':
	case 'u':		/* what a joke */
		b = 10;
		goto number;
	case 'o': case 'O':
		b = 8;
number:
		printn(va_arg(ap, unsigned), b, flags, ttyp, zf, fld_size);
		break;
	case 'c':
		b = va_arg(ap, unsigned);
#if BYTE_ORDER == LITTLE_ENDIAN
		for (i = 24; i >= 0; i -= 8)
			if (c = (b >> i) & 0x7f)
				putchar(c, flags, ttyp);
#endif
#if BYTE_ORDER == BIG_ENDIAN
		if ((c = (b & 0x7f)))
			putchar(c, flags, ttyp);
#endif
		break;
	case 'b':
		b = va_arg(ap, unsigned);
		s = va_arg(ap, char *);
		printn((u_long)b, *s++, flags, ttyp, 0, 0);
		any = 0;
		if (b) {
			while ((i = *s++)) {
				if (*s <= 32) {
					register int j;

					if (any++)
						putchar(',', flags, ttyp);
					j = *s++ ;
					for (; (c = *s) > 32 ; s++)
						putchar(c, flags, ttyp);
					printn( (u_long)( (b >> (j-1)) &
							 ( (2 << (i-j)) -1)),
						 8, flags, ttyp, 0, 0);
				} else if (b & (1 << (i-1))) {
					putchar(any? ',' : '<', flags, ttyp);
					any = 1;
					for (; (c = *s) > 32; s++)
						putchar(c, flags, ttyp);
				} else
					for (; *s > 32; s++)
						;
			}
			putchar('>', flags, ttyp);
		}
		break;

	case 's':
		s = va_arg(ap, char *);
#ifdef DEBUG
		if (fld_size) {
			while (fld_size-- > 0)
				putchar((c = *s++)? c : '_', flags, ttyp);
		} else {
			while ((c = *s++))
				putchar(c, flags, ttyp);
		}
#else	
		while (c = *s++)
			putchar(c, flags, ttyp);
#endif
		break;

	case '%':
		putchar('%', flags, ttyp);
		goto loop;
	case 'C':
		b = va_arg(ap, unsigned);
#if BYTE_ORDER == LITTLE_ENDIAN
		for (i = 24; i >= 0; i -= 8)
			if (c = (b >> i) & 0x7f)
				putchar(c, flags, ttyp);
#endif
#if BYTE_ORDER == BIG_ENDIAN
		if ((c = (b & 0x7f)))
			putchar(c, flags, ttyp);
#endif

	case 'r':
	case 'R':
		b = va_arg(ap, unsigned);
		s = va_arg(ap, char *);
		if (c == 'R') {
			puts("0x", flags, ttyp);
			printn((u_long)b, 16, flags, ttyp, 0, 0);
		}
		any = 0;
		if (c == 'r' || b) {
			register struct reg_desc *rd;
			register struct reg_values *rv;
			unsigned field;

			putchar('<', flags, ttyp);
			for (rd = (struct reg_desc *)s; rd->rd_mask; rd++) {
				field = b & rd->rd_mask;
				field = (rd->rd_shift > 0)
				    ? field << rd->rd_shift
				    : field >> -rd->rd_shift;
				if (any &&
				      (rd->rd_format || rd->rd_values
				         || (rd->rd_name && field)
				      )
				)
					putchar(',', flags, ttyp);
				if (rd->rd_name) {
					if (rd->rd_format || rd->rd_values
					    || field) {
						puts(rd->rd_name, flags, ttyp);
						any = 1;
					}
					if (rd->rd_format || rd->rd_values) {
						putchar('=', flags, ttyp);
						any = 1;
					}
				}
				if (rd->rd_format) {
					_printf(flags, ttyp, rd->rd_format,
					  field);
					any = 1;
					if (rd->rd_values)
						putchar(':', flags, ttyp);
				}
				if (rd->rd_values) {
					any = 1;
					for (rv = rd->rd_values;
					    rv->rv_name;
					    rv++) {
						if (field == rv->rv_value) {
							puts(rv->rv_name, flags,
							    ttyp);
							break;
						}
					}
					if (rv->rv_name == NULL)
						puts("???", flags, ttyp);
				}
			}
			putchar('>', flags, ttyp);
		}
		break;

	case 'n':
	case 'N':
		{
			register struct reg_values *rv;

			b = va_arg(ap, unsigned);
			s = va_arg(ap,char *);
			for (rv = (struct reg_values *)s; rv->rv_name; rv++) {
				if (b == rv->rv_value) {
					puts(rv->rv_name, flags, ttyp);
					break;
				}
			}
			if (rv->rv_name == NULL)
				puts("???", flags, ttyp);
			if (c == 'N' || rv->rv_name == NULL) {
				putchar(':', flags, ttyp);
				printn((u_long)b, 10, flags, ttyp, 0, 0);
			}
		}
		break;
	}
	goto loop;
}

static void puts(const char *s, int flags, struct tty *ttyp)
{
	register char c;

	while ((c = *s++))
		putchar(c, flags, ttyp);
}

/*
 * Printn prints a number n in base b.
 * We don't use recursion to avoid deep kernel stacks.
 */
static void printn(u_long n, int b, int flags, struct tty *ttyp, int zf, int fld_size)
{
	char prbuf[11];
	register char *cp;

	if (b == 10 && (int)n < 0) {
		putchar('-', flags, ttyp);
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
				putchar('0', flags, ttyp);
			else
				putchar(' ', flags, ttyp);
	}
	do
		putchar(*--cp, flags, ttyp);
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
 */
/*ARGSUSED*/
int
putchar(c, flags, tp)
	register int c;
	struct tty *tp;
{
	register struct msgbuf *mbp;
	char **sp = (char**) tp;

	if (panicstr)
		constty = 0;
	if ((flags & TOCONS) && tp == NULL && constty) {
		tp = constty;
		flags |= TOTTY;
	}
	if ((flags & TOTTY) && tp && tputchar(c, tp) < 0 &&
	    (flags & TOCONS) && tp == constty)
		constty = 0;
	if ((flags & TOLOG) && c != '\0' && c != '\r' && c != 0177)
		log_putc(c);
	if ((flags & TOCONS) && constty == 0 && c != '\0')
		(*v_putc)(c);
	if (flags & TOSTR) {
		**sp = c;
		(*sp)++;
	}
	return 0;
}



/*
 * Scaled down version of vsprintf(3).
 */
int
vsprintf(char *buf, const char *cfmt, va_list ap)
{
	int retval;

	retval = kvprintf(cfmt, NULL, (void *)buf, 10, ap);
	buf[retval] = '\0';
	return retval;
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
	retval = kvprintf(format, snprintf_func, &info, 10, ap);
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

/*
 * Put a number (base <= 16) in a buffer in reverse order; return an
 * optional length and a pointer to the NULL terminated (preceded?)
 * buffer.
 */
static char *
ksprintn(ul, base, lenp)
	register u_long ul;
	register int base, *lenp;
{					/* A long in base 8, plus NULL. */
	static char buf[sizeof(long) * NBBY / 3 + 2];
	register char *p;

	p = buf;
	do {
		*++p = hex2ascii(ul % base);
	} while (ul /= base);
	if (lenp)
		*lenp = p - buf;
	return (p);
}

/*
 * Scaled down version of printf(3).
 *
 * Two additional formats:
 *
 * The format %b is supported to decode error registers.
 * Its usage is:
 *
 *	printf("reg=%b\n", regval, "<base><arg>*");
 *
 * where <base> is the output base expressed as a control character, e.g.
 * \10 gives octal; \20 gives hex.  Each arg is a sequence of characters,
 * the first of which gives the bit number to be inspected (origin 1), and
 * the next characters (up to a control character, i.e. a character <= 32),
 * give the name of the register.  Thus:
 *
 *	kvprintf("reg=%b\n", 3, "\10\2BITTWO\1BITONE\n");
 *
 * would produce output:
 *
 *	reg=3<BITTWO,BITONE>
 *
 * XXX:  %D  -- Hexdump, takes pointer and separator string:
 *		("%6D", ptr, ":")   -> XX:XX:XX:XX:XX:XX
 *		("%*D", len, ptr, " " -> XX XX XX XX ...
 */
int
kvprintf(char const *fmt, void (*func)(int, void*), void *arg, int radix, va_list ap)
{
#define PCHAR(c) {int cc=(c); if (func) (*func)(cc,arg); else *d++ = cc; retval++; }
	char *p, *q, *d;
	u_char *up;
	int ch, n;
	u_long ul;
	int base, lflag, tmp, width, ladjust, sharpflag, neg, sign, dot;
	int dwidth;
	char padc;
	int retval = 0;

	if (!func)
		d = (char *) arg;
	else
		d = NULL;

	if (fmt == NULL)
		fmt = "(fmt null)\n";

	if (radix < 2 || radix > 36)
		radix = 10;

	for (;;) {
		padc = ' ';
		width = 0;
		while ((ch = (u_char)*fmt++) != '%') {
			if (ch == '\0') 
				return retval;
			PCHAR(ch);
		}
		lflag = 0; ladjust = 0; sharpflag = 0; neg = 0;
		sign = 0; dot = 0; dwidth = 0;
reswitch:	switch (ch = (u_char)*fmt++) {
		case '.':
			dot = 1;
			goto reswitch;
		case '#':
			sharpflag = 1;
			goto reswitch;
		case '+':
			sign = 1;
			goto reswitch;
		case '-':
			ladjust = 1;
			goto reswitch;
		case '%':
			PCHAR(ch);
			break;
		case '*':
			if (!dot) {
				width = va_arg(ap, int);
				if (width < 0) {
					ladjust = !ladjust;
					width = -width;
				}
			} else {
				dwidth = va_arg(ap, int);
			}
			goto reswitch;
		case '0':
			if (!dot) {
				padc = '0';
				goto reswitch;
			}
		case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
				for (n = 0;; ++fmt) {
					n = n * 10 + ch - '0';
					ch = *fmt;
					if (ch < '0' || ch > '9')
						break;
				}
			if (dot)
				dwidth = n;
			else
				width = n;
			goto reswitch;
		case 'b':
			ul = va_arg(ap, int);
			p = va_arg(ap, char *);
			for (q = ksprintn(ul, *p++, NULL); *q;)
				PCHAR(*q--);

			if (!ul)
				break;

			for (tmp = 0; *p;) {
				n = *p++;
				if (ul & (1 << (n - 1))) {
					PCHAR(tmp ? ',' : '<');
					for (; (n = *p) > ' '; ++p)
						PCHAR(n);
					tmp = 1;
				} else
					for (; *p > ' '; ++p)
						continue;
			}
			if (tmp)
				PCHAR('>');
			break;
		case 'c':
			PCHAR(va_arg(ap, int));
			break;
		case 'D':
			up = va_arg(ap, u_char *);
			p = va_arg(ap, char *);
			if (!width)
				width = 16;
			while(width--) {
				PCHAR(hex2ascii(*up >> 4));
				PCHAR(hex2ascii(*up & 0x0f));
				up++;
				if (width)
					for (q=p;*q;q++)
						PCHAR(*q);
			}
			break;
		case 'd':
			ul = lflag ? va_arg(ap, long) : va_arg(ap, int);
			sign = 1;
			base = 10;
			goto number;
		case 'l':
			lflag = 1;
			goto reswitch;
		case 'o':
			ul = lflag ? va_arg(ap, u_long) : va_arg(ap, u_int);
			base = 8;
			goto nosign;
		case 'p':
			ul = (uintptr_t)va_arg(ap, void *);
			base = 16;
			sharpflag = (width == 0);
			goto nosign;
		case 'n':
		case 'r':
			ul = lflag ? va_arg(ap, u_long) :
			    sign ? (u_long)va_arg(ap, int) : va_arg(ap, u_int);
			base = radix;
			goto number;
		case 's':
			p = va_arg(ap, char *);
			if (p == NULL)
				p = "(null)";
			if (!dot)
				n = strlen (p);
			else
				for (n = 0; n < dwidth && p[n]; n++)
					continue;

			width -= n;

			if (!ladjust && width > 0)
				while (width--)
					PCHAR(padc);
			while (n--)
				PCHAR(*p++);
			if (ladjust && width > 0)
				while (width--)
					PCHAR(padc);
			break;
		case 'u':
			ul = lflag ? va_arg(ap, u_long) : va_arg(ap, u_int);
			base = 10;
			goto nosign;
		case 'x':
			ul = lflag ? va_arg(ap, u_long) : va_arg(ap, u_int);
			base = 16;
			goto nosign;
		case 'z':
			ul = lflag ? va_arg(ap, u_long) :
			    sign ? (u_long)va_arg(ap, int) : va_arg(ap, u_int);
			base = 16;
			goto number;
nosign:			sign = 0;
number:			if (sign && (long)ul < 0L) {
				neg = 1;
				ul = -(long)ul;
			}
			p = ksprintn(ul, base, &tmp);
			if (sharpflag && ul != 0) {
				if (base == 8)
					tmp++;
				else if (base == 16)
					tmp += 2;
			}
			if (neg)
				tmp++;

			if (!ladjust && width && (width -= tmp) > 0)
				while (width--)
					PCHAR(padc);
			if (neg)
				PCHAR('-');
			if (sharpflag && ul != 0) {
				if (base == 8) {
					PCHAR('0');
				} else if (base == 16) {
					PCHAR('0');
					PCHAR('x');
				}
			}

			while (*p)
				PCHAR(*p--);

			if (ladjust && width && (width -= tmp) > 0)
				while (width--)
					PCHAR(padc);

			break;
		default:
			PCHAR('%');
			if (lflag)
				PCHAR('l');
			PCHAR(ch);
			break;
		}
	}
#undef PCHAR
}
