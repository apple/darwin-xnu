/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1982, 1986, 1991, 1993
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
 *	@(#)subr_xxx.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/proc_internal.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/sysproto.h>

#include <sys/signalvar.h>		/* for psignal() */
#include <kern/debug.h>

#ifdef GPROF
#include <sys/gmon.h>
#endif

#if DEVELOPMENT || DEBUG
bool send_sigsys = true;
#else
#define send_sigsys true
#endif

/*
 * Unsupported device function (e.g. writing to read-only device).
 */
int
enodev(void)
{
	return (ENODEV);
}

/* 
 * Unsupported strategy function.
 */
void
enodev_strat(void)
{
	return;
}

/*
 * Unconfigured device function; driver not configured.
 */
int
enxio(void)
{
	return (ENXIO);
}

/*
 * Unsupported ioctl function.
 */
int
enoioctl(void)
{
	return (ENOTTY);
}


/*
 * Unsupported system function.
 * This is used for an otherwise-reasonable operation
 * that is not supported by the current system binary.
 */
int
enosys(void)
{
	return (ENOSYS);
}

/*
 * Return error for operation not supported
 * on a specific object or file type.
 *
 * XXX Name of this routine is wrong.
 */
int
eopnotsupp(void)
{
	return (ENOTSUP);
}

/*
 * Generic null operation, always returns success.
 */
int
nullop(void)
{
	return (0);
}


/*
 * Null routine; placed in insignificant entries
 * in the bdevsw and cdevsw tables.
 */
int
nulldev(void)
{
	return (0);
}

/*
 * Null system calls. Not invalid, just not configured.
 */
int
errsys(void)
{
	return(EINVAL);
}

void
nullsys(void)
{
}

/*
 * nonexistent system call-- signal process (may want to handle it)
 * flag error if process won't see signal immediately
 * Q: should we do that all the time ??
 */
/* ARGSUSED */
int
nosys(__unused struct proc *p, __unused struct nosys_args *args, __unused int32_t *retval)
{
	if (send_sigsys) {
		psignal_uthread(current_thread(), SIGSYS);
	}
	return (ENOSYS);
}

#ifdef	GPROF
/*
 * Stub routine in case it is ever possible to free space.
 */
void
cfreemem(caddr_t cp, int size)
{
	printf("freeing %p, size %d\n", cp, size);
}
#endif

#if !CRYPTO
#include <crypto/rc4/rc4.h>

/* Stubs must be present in all configs for Unsupported KPI exports */

void
rc4_init(struct rc4_state *state __unused, const u_char *key __unused, int keylen __unused)
{
	panic("rc4_init: unsupported kernel configuration");
}

void
rc4_crypt(struct rc4_state *state __unused,
		  const u_char *inbuf __unused, u_char *outbuf __unused, int buflen __unused)
{
	panic("rc4_crypt: unsupported kernel configuration");
}
#endif /* !CRYPTO */

