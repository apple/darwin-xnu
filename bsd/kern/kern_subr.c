/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1991, 1993
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
 *	@(#)kern_subr.c	8.3 (Berkeley) 1/21/94
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/malloc.h>
#include <sys/queue.h>

#include <kdebug.h>

#include <sys/kdebug.h>
#define DBG_UIO_COPYOUT 16
#define DBG_UIO_COPYIN  17


int
uiomove(cp, n, uio)
	register caddr_t cp;
	register int n;
	register struct uio *uio;
{
	register struct iovec *iov;
	u_int cnt;
	int error = 0;

#if DIAGNOSTIC
	if (uio->uio_rw != UIO_READ && uio->uio_rw != UIO_WRITE)
		panic("uiomove: mode");
	if (uio->uio_segflg == UIO_USERSPACE && uio->uio_procp != current_proc())
		panic("uiomove proc");
#endif

	while (n > 0 && uio->uio_resid) {
		iov = uio->uio_iov;
		cnt = iov->iov_len;
		if (cnt == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			continue;
		}
		if (cnt > n)
			cnt = n;
		switch (uio->uio_segflg) {

		case UIO_USERSPACE:
		case UIO_USERISPACE:
			if (uio->uio_rw == UIO_READ)
			  {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_START,
					 cp, iov->iov_base, cnt, 0,0);

				error = copyout(cp, iov->iov_base, cnt);

			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_END,
					 cp, iov->iov_base, cnt, 0,0);
			  }
			else
			  {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_START,
					 iov->iov_base, cp, cnt, 0,0);

			        error = copyin(iov->iov_base, cp, cnt);

			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_END,
					 iov->iov_base, cp, cnt, 0,0);
			  }
			if (error)
				return (error);
			break;

		case UIO_SYSSPACE:
			if (uio->uio_rw == UIO_READ)
				error = copywithin((caddr_t)cp, iov->iov_base,
						   cnt);
			else
				error = copywithin(iov->iov_base, (caddr_t)cp,
						   cnt);
			break;

		case UIO_PHYS_USERSPACE:
			if (uio->uio_rw == UIO_READ)
			  {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_START,
					 cp, iov->iov_base, cnt, 1,0);

				error = copyp2v(cp, iov->iov_base, cnt);


			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_END,
					 cp, iov->iov_base, cnt, 1,0);
			  }
			else
			  {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_START,
					 iov->iov_base, cp, cnt, 1,0);

				panic("copyv2p not implemented yet\n");

			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_END,
					 iov->iov_base, cp, cnt, 1,0);
			  }
			if (error)
				return (error);
			break;
		}
		iov->iov_base += cnt;
		iov->iov_len -= cnt;
		uio->uio_resid -= cnt;
		uio->uio_offset += cnt;
		cp += cnt;
		n -= cnt;
	}
	return (error);
}

/*
 * Give next character to user as result of read.
 */
int
ureadc(c, uio)
	register int c;
	register struct uio *uio;
{
	register struct iovec *iov;

	if (uio->uio_resid <= 0)
		panic("ureadc: non-positive resid");
again:
	if (uio->uio_iovcnt == 0)
		panic("ureadc: non-positive iovcnt");
	iov = uio->uio_iov;
	if (iov->iov_len <= 0) {
		uio->uio_iovcnt--;
		uio->uio_iov++;
		goto again;
	}
	switch (uio->uio_segflg) {

	case UIO_USERSPACE:
		if (subyte(iov->iov_base, c) < 0)
			return (EFAULT);
		break;

	case UIO_SYSSPACE:
		*iov->iov_base = c;
		break;

	case UIO_USERISPACE:
		if (suibyte(iov->iov_base, c) < 0)
			return (EFAULT);
		break;
	}
	iov->iov_base++;
	iov->iov_len--;
	uio->uio_resid--;
	uio->uio_offset++;
	return (0);
}

#if defined(vax) || defined(ppc)
/* unused except by ct.c, other oddities XXX */
/*
 * Get next character written in by user from uio.
 */
uwritec(uio)
	struct uio *uio;
{
	register struct iovec *iov;
	register int c;

	if (uio->uio_resid <= 0)
		return (-1);
again:
	if (uio->uio_iovcnt <= 0)
		panic("uwritec: non-positive iovcnt");
	iov = uio->uio_iov;
	if (iov->iov_len == 0) {
		uio->uio_iov++;
		if (--uio->uio_iovcnt == 0)
			return (-1);
		goto again;
	}
	switch (uio->uio_segflg) {

	case UIO_USERSPACE:
		c = fubyte(iov->iov_base);
		break;

	case UIO_SYSSPACE:
		c = *iov->iov_base & 0377;
		break;

	case UIO_USERISPACE:
		c = fuibyte(iov->iov_base);
		break;

	default:
		c = 0;	/* avoid uninitialized variable warning */
		panic("uwritec: bogus uio_segflg");
		break;
	}
	if (c < 0)
		return (-1);
	iov->iov_base++;
	iov->iov_len--;
	uio->uio_resid--;
	uio->uio_offset++;
	return (c);
}
#endif /* vax || ppc */

/*
 * General routine to allocate a hash table.
 */
void *
hashinit(elements, type, hashmask)
	int elements, type;
	u_long *hashmask;
{
	long hashsize;
	LIST_HEAD(generic, generic) *hashtbl;
	int i;

	if (elements <= 0)
		panic("hashinit: bad cnt");
	for (hashsize = 1; hashsize <= elements; hashsize <<= 1)
		continue;
	hashsize >>= 1;
	MALLOC(hashtbl, struct generic *, 
			(u_long)hashsize * sizeof(*hashtbl), type, M_WAITOK);
	bzero(hashtbl, (u_long)hashsize * sizeof(*hashtbl));
	for (i = 0; i < hashsize; i++)
		LIST_INIT(&hashtbl[i]);
	*hashmask = hashsize - 1;
	return (hashtbl);
}
