/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
#include <sys/proc_internal.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <vm/pmap.h>
#include <sys/uio_internal.h>
#include <kern/kalloc.h>

#include <kdebug.h>

#include <sys/kdebug.h>
#define DBG_UIO_COPYOUT 16
#define DBG_UIO_COPYIN  17

#if DEBUG
#include <kern/simple_lock.h>

static int				uio_t_count = 0;
#endif /* DEBUG */


int
uiomove(cp, n, uio)
	register caddr_t cp;
	register int n;
	register uio_t uio;
{
	return uiomove64((addr64_t)((unsigned int)cp), n, uio);
}

	// LP64todo - fix this! 'n' should be int64_t?
int
uiomove64(addr64_t cp, int n, register struct uio *uio)
{
#if LP64KERN
	register uint64_t acnt;
#else
	register u_int acnt;
#endif
	int error = 0;

#if DIAGNOSTIC
	if (uio->uio_rw != UIO_READ && uio->uio_rw != UIO_WRITE)
		panic("uiomove: mode");
#endif

#if LP64_DEBUG
	if (IS_VALID_UIO_SEGFLG(uio->uio_segflg) == 0) {
		panic("%s :%d - invalid uio_segflg\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	while (n > 0 && uio_resid(uio)) {
		acnt = uio_iov_len(uio);
		if (acnt == 0) {
			uio_next_iov(uio);
			uio->uio_iovcnt--;
			continue;
		}
		if (n > 0 && acnt > (uint64_t)n)
			acnt = n;

		switch (uio->uio_segflg) {

		case UIO_USERSPACE64:
		case UIO_USERISPACE64:
			// LP64 - 3rd argument in debug code is 64 bit, expected to be 32 bit
			if (uio->uio_rw == UIO_READ)
			  {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_START,
					 (int)cp, (int)uio->uio_iovs.iov64p->iov_base, acnt, 0,0);

					error = copyout( CAST_DOWN(caddr_t, cp), uio->uio_iovs.iov64p->iov_base, acnt );

			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_END,
					 (int)cp, (int)uio->uio_iovs.iov64p->iov_base, acnt, 0,0);
			  }
			else
			  {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_START,
					 (int)uio->uio_iovs.iov64p->iov_base, (int)cp, acnt, 0,0);

			        error = copyin(uio->uio_iovs.iov64p->iov_base, CAST_DOWN(caddr_t, cp), acnt);

			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_END,
					 (int)uio->uio_iovs.iov64p->iov_base, (int)cp, acnt, 0,0);
			  }
			if (error)
				return (error);
			break;

		case UIO_USERSPACE32:
		case UIO_USERISPACE32:
		case UIO_USERSPACE:
		case UIO_USERISPACE:
			if (uio->uio_rw == UIO_READ)
			  {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_START,
					 (int)cp, (int)uio->uio_iovs.iov32p->iov_base, acnt, 0,0);

					error = copyout( CAST_DOWN(caddr_t, cp), CAST_USER_ADDR_T(uio->uio_iovs.iov32p->iov_base), acnt );

			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_END,
					 (int)cp, (int)uio->uio_iovs.iov32p->iov_base, acnt, 0,0);
			  }
			else
			  {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_START,
					 (int)uio->uio_iovs.iov32p->iov_base, (int)cp, acnt, 0,0);

			        error = copyin(CAST_USER_ADDR_T(uio->uio_iovs.iov32p->iov_base), CAST_DOWN(caddr_t, cp), acnt);

			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_END,
					 (int)uio->uio_iovs.iov32p->iov_base, (int)cp, acnt, 0,0);
			  }
			if (error)
				return (error);
			break;

		case UIO_SYSSPACE32:
		case UIO_SYSSPACE:
			if (uio->uio_rw == UIO_READ)
				error = copywithin(CAST_DOWN(caddr_t, cp), (caddr_t)uio->uio_iovs.iov32p->iov_base,
						   acnt);
			else
				error = copywithin((caddr_t)uio->uio_iovs.iov32p->iov_base, CAST_DOWN(caddr_t, cp),
						   acnt);
			break;

		case UIO_PHYS_USERSPACE64:
			if (uio->uio_rw == UIO_READ)
			  {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_START,
					 (int)cp, (int)uio->uio_iovs.iov64p->iov_base, acnt, 1,0);

				error = copypv((addr64_t)cp, uio->uio_iovs.iov64p->iov_base, acnt, cppvPsrc | cppvNoRefSrc);
				if (error) 	/* Copy physical to virtual */
				        error = EFAULT;

			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_END,
					 (int)cp, (int)uio->uio_iovs.iov64p->iov_base, acnt, 1,0);
			  }
			else
			  {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_START,
					 (int)uio->uio_iovs.iov64p->iov_base, (int)cp, acnt, 1,0);

				error = copypv(uio->uio_iovs.iov64p->iov_base, (addr64_t)cp, acnt, cppvPsnk | cppvNoRefSrc | cppvNoModSnk);
				if (error)	/* Copy virtual to physical */
				        error = EFAULT;

			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_END,
					 (int)uio->uio_iovs.iov64p->iov_base, (int)cp, acnt, 1,0);
			  }
			if (error)
				return (error);
			break;

		case UIO_PHYS_USERSPACE32:
		case UIO_PHYS_USERSPACE:
			if (uio->uio_rw == UIO_READ)
			  {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_START,
					 (int)cp, (int)uio->uio_iovs.iov32p->iov_base, acnt, 1,0);

				error = copypv((addr64_t)cp, (addr64_t)uio->uio_iovs.iov32p->iov_base, acnt, cppvPsrc | cppvNoRefSrc);
				if (error) 	/* Copy physical to virtual */
				        error = EFAULT;

			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_END,
					 (int)cp, (int)uio->uio_iovs.iov32p->iov_base, acnt, 1,0);
			  }
			else
			  {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_START,
					 (int)uio->uio_iovs.iov32p->iov_base, (int)cp, acnt, 1,0);

				error = copypv((addr64_t)uio->uio_iovs.iov32p->iov_base, (addr64_t)cp, acnt, cppvPsnk | cppvNoRefSrc | cppvNoModSnk);
				if (error)	/* Copy virtual to physical */
				        error = EFAULT;

			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_END,
					 (int)uio->uio_iovs.iov32p->iov_base, (int)cp, acnt, 1,0);
			  }
			if (error)
				return (error);
			break;

		case UIO_PHYS_SYSSPACE32:
		case UIO_PHYS_SYSSPACE:
			if (uio->uio_rw == UIO_READ)
			  {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_START,
					 (int)cp, (int)uio->uio_iovs.iov32p->iov_base, acnt, 2,0);

				error = copypv((addr64_t)cp, uio->uio_iovs.iov32p->iov_base, acnt, cppvKmap | cppvPsrc | cppvNoRefSrc);
				if (error) 	/* Copy physical to virtual */
				        error = EFAULT;

			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYOUT)) | DBG_FUNC_END,
					 (int)cp, (int)uio->uio_iovs.iov32p->iov_base, acnt, 2,0);
			  }
			else
			  {
			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_START,
					 (int)uio->uio_iovs.iov32p->iov_base, (int)cp, acnt, 2,0);

				error = copypv(uio->uio_iovs.iov32p->iov_base, (addr64_t)cp, acnt, cppvKmap | cppvPsnk | cppvNoRefSrc | cppvNoModSnk);
				if (error)	/* Copy virtual to physical */
				        error = EFAULT;

			        KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, DBG_UIO_COPYIN)) | DBG_FUNC_END,
					 (int)uio->uio_iovs.iov32p->iov_base, (int)cp, acnt, 2,0);
			  }
			if (error)
				return (error);
			break;

		default:
			break;
		}
		uio_iov_base_add(uio, acnt);
#if LP64KERN
		uio_iov_len_add(uio, -((int64_t)acnt));
		uio_setresid(uio, (uio_resid(uio) - ((int64_t)acnt)));
#else
		uio_iov_len_add(uio, -((int)acnt));
		uio_setresid(uio, (uio_resid(uio) - ((int)acnt)));
#endif
		uio->uio_offset += acnt;
		cp += acnt;
		n -= acnt;
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
	if (uio_resid(uio) <= 0)
		panic("ureadc: non-positive resid");
again:
	if (uio->uio_iovcnt == 0)
		panic("ureadc: non-positive iovcnt");
	if (uio_iov_len(uio) <= 0) {
		uio->uio_iovcnt--;
		uio_next_iov(uio);
		goto again;
	}
	switch (uio->uio_segflg) {

	case UIO_USERSPACE32:
	case UIO_USERSPACE:
		if (subyte(CAST_USER_ADDR_T(uio->uio_iovs.iov32p->iov_base), c) < 0)
			return (EFAULT);
		break;

	case UIO_USERSPACE64:
		if (subyte((user_addr_t)uio->uio_iovs.iov64p->iov_base, c) < 0)
			return (EFAULT);
		break;

	case UIO_SYSSPACE32:
	case UIO_SYSSPACE:
		*((caddr_t)uio->uio_iovs.iov32p->iov_base) = c;
		break;

	case UIO_USERISPACE32:
	case UIO_USERISPACE:
		if (suibyte(CAST_USER_ADDR_T(uio->uio_iovs.iov32p->iov_base), c) < 0)
			return (EFAULT);
		break;

	default:
		break;
	}
	uio_iov_base_add(uio, 1);
	uio_iov_len_add(uio, -1);
	uio_setresid(uio, (uio_resid(uio) - 1));
	uio->uio_offset++;
	return (0);
}

#if defined(vax) || defined(ppc)
/* unused except by ct.c, other oddities XXX */
/*
 * Get next character written in by user from uio.
 */
int
uwritec(uio)
	uio_t uio;
{
	register int c = 0;

	if (uio_resid(uio) <= 0)
		return (-1);
again:
	if (uio->uio_iovcnt <= 0)
		panic("uwritec: non-positive iovcnt");

	if (uio_iov_len(uio) == 0) {
		uio_next_iov(uio);
		if (--uio->uio_iovcnt == 0)
			return (-1);
		goto again;
	}
	switch (uio->uio_segflg) {

	case UIO_USERSPACE32:
	case UIO_USERSPACE:
		c = fubyte(CAST_USER_ADDR_T(uio->uio_iovs.iov32p->iov_base));
		break;

	case UIO_USERSPACE64:
		c = fubyte((user_addr_t)uio->uio_iovs.iov64p->iov_base); 
		break;

	case UIO_SYSSPACE32:
	case UIO_SYSSPACE:
		c = *((caddr_t)uio->uio_iovs.iov32p->iov_base) & 0377;
		break;

	case UIO_USERISPACE32:
	case UIO_USERISPACE:
		c = fuibyte(CAST_USER_ADDR_T(uio->uio_iovs.iov32p->iov_base));
		break;

	default:
		c = 0;	/* avoid uninitialized variable warning */
		panic("uwritec: bogus uio_segflg");
		break;
	}
	if (c < 0)
		return (-1);
	uio_iov_base_add(uio, 1);
	uio_iov_len_add(uio, -1);
	uio_setresid(uio, (uio_resid(uio) - 1));
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
		(u_long)hashsize * sizeof(*hashtbl), type, M_WAITOK|M_ZERO);
	if (hashtbl != NULL) {
		for (i = 0; i < hashsize; i++)
			LIST_INIT(&hashtbl[i]);
		*hashmask = hashsize - 1;
	}
	return (hashtbl);
}

/*
 * uio_resid - return the residual IO value for the given uio_t
 */
user_ssize_t uio_resid( uio_t a_uio )
{
#if DEBUG
	if (a_uio == NULL) {
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
	}
/* 	if (IS_VALID_UIO_SEGFLG(a_uio->uio_segflg) == 0) { */
/* 		panic("%s :%d - invalid uio_segflg\n", __FILE__, __LINE__);  */
/* 	} */
#endif /* DEBUG */

	/* return 0 if there are no active iovecs */
	if (a_uio == NULL) {
		return( 0 );
	}

	if (UIO_IS_64_BIT_SPACE(a_uio)) {
#if 1 // LP64todo - remove this temp workaround once we go live with uio KPI
		return( (user_ssize_t)a_uio->uio_resid );
#else
		return( a_uio->uio_resid_64 );
#endif
	}
	return( (user_ssize_t)a_uio->uio_resid );
}

/*
 * uio_setresid - set the residual IO value for the given uio_t
 */
void uio_setresid( uio_t a_uio, user_ssize_t a_value )
{
#if DEBUG
	if (a_uio == NULL) {
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
	}
/* 	if (IS_VALID_UIO_SEGFLG(a_uio->uio_segflg) == 0) { */
/* 		panic("%s :%d - invalid uio_segflg\n", __FILE__, __LINE__);  */
/* 	} */
#endif /* DEBUG */

	if (a_uio == NULL) {
		return;
	}

	if (UIO_IS_64_BIT_SPACE(a_uio)) {
#if 1 // LP64todo - remove this temp workaround once we go live with uio KPI
		a_uio->uio_resid = (int)a_value;
#else
		a_uio->uio_resid_64 = a_value;
#endif
	}
	else {
		a_uio->uio_resid = (int)a_value;
	}
	return;
}

#if 0 // obsolete
/*
 * uio_proc_t - return the proc_t for the given uio_t
 * WARNING - This call is going away.  Find another way to get the proc_t!!
 */
__private_extern__ proc_t uio_proc_t( uio_t a_uio )
{
#if LP64_DEBUG
	if (a_uio == NULL) {
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	/* return 0 if there are no active iovecs */
	if (a_uio == NULL) {
		return( NULL );
	}
	return( a_uio->uio_procp );
}

/*
 * uio_setproc_t - set the residual IO value for the given uio_t
 * WARNING - This call is going away. 
 */
__private_extern__ void uio_setproc_t( uio_t a_uio, proc_t a_proc_t )
{
	if (a_uio == NULL) {
#if LP64_DEBUG
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
#endif /* LP64_DEBUG */
		return;
	}

	a_uio->uio_procp = a_proc_t;
	return;
}
#endif // obsolete

/*
 * uio_curriovbase - return the base address of the current iovec associated 
 *	with the given uio_t.  May return 0.
 */
user_addr_t uio_curriovbase( uio_t a_uio )
{
#if LP64_DEBUG
	if (a_uio == NULL) {
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	if (a_uio == NULL || a_uio->uio_iovcnt < 1) {
		return(0);
	}
	
	if (UIO_IS_64_BIT_SPACE(a_uio)) {
		return(a_uio->uio_iovs.uiovp->iov_base);
	}
	return((user_addr_t)((uintptr_t)a_uio->uio_iovs.kiovp->iov_base));
	
}

/*
 * uio_curriovlen - return the length value of the current iovec associated 
 *	with the given uio_t.
 */
user_size_t uio_curriovlen( uio_t a_uio )
{
#if LP64_DEBUG
	if (a_uio == NULL) {
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	if (a_uio == NULL || a_uio->uio_iovcnt < 1) {
		return(0);
	}
	
	if (UIO_IS_64_BIT_SPACE(a_uio)) {
		return(a_uio->uio_iovs.uiovp->iov_len);
	}
	return((user_size_t)a_uio->uio_iovs.kiovp->iov_len);
}

/*
 * uio_setcurriovlen - set the length value of the current iovec associated 
 *	with the given uio_t.
 */
__private_extern__ void uio_setcurriovlen( uio_t a_uio, user_size_t a_value )
{
#if LP64_DEBUG
	if (a_uio == NULL) {
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	if (a_uio == NULL) {
		return; 
	}

	if (UIO_IS_64_BIT_SPACE(a_uio)) {
		a_uio->uio_iovs.uiovp->iov_len = a_value;
	}
	else {
#if LP64_DEBUG
		if (a_value > 0xFFFFFFFFull) {
			panic("%s :%d - invalid a_value\n", __FILE__, __LINE__); 
		}
#endif /* LP64_DEBUG */
		a_uio->uio_iovs.kiovp->iov_len = (size_t)a_value;
	}
	return;
}

/*
 * uio_iovcnt - return count of active iovecs for the given uio_t
 */
int uio_iovcnt( uio_t a_uio )
{
#if LP64_DEBUG
	if (a_uio == NULL) {
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	if (a_uio == NULL) {
		return(0); 
	}

	return( a_uio->uio_iovcnt );
}

/*
 * uio_offset - return the current offset value for the given uio_t
 */
off_t uio_offset( uio_t a_uio )
{
#if LP64_DEBUG
	if (a_uio == NULL) {
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	if (a_uio == NULL) {
		return(0); 
	}
	return( a_uio->uio_offset );
}

/*
 * uio_setoffset - set the current offset value for the given uio_t
 */
void uio_setoffset( uio_t a_uio, off_t a_offset )
{
#if LP64_DEBUG
	if (a_uio == NULL) {
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	if (a_uio == NULL) {
		return; 
	}
	a_uio->uio_offset = a_offset;
	return;
}

/*
 * uio_rw - return the read / write flag for the given uio_t
 */
int uio_rw( uio_t a_uio )
{
#if LP64_DEBUG
	if (a_uio == NULL) {
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	if (a_uio == NULL) {
		return(-1); 
	}
	return( a_uio->uio_rw );
}

/*
 * uio_setrw - set the read / write flag for the given uio_t
 */
void uio_setrw( uio_t a_uio, int a_value )
{
	if (a_uio == NULL) {
#if LP64_DEBUG
	panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
#endif /* LP64_DEBUG */
		return;
	}

#if LP64_DEBUG
	if (!(a_value == UIO_READ || a_value == UIO_WRITE)) {
		panic("%s :%d - invalid a_value\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	if (a_value == UIO_READ || a_value == UIO_WRITE) {
		a_uio->uio_rw = a_value;
	}
	return;
}

/*
 * uio_isuserspace - return non zero value if the address space 
 * flag is for a user address space (could be 32 or 64 bit).
 */
int uio_isuserspace( uio_t a_uio )
{
	if (a_uio == NULL) {
#if LP64_DEBUG
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
#endif /* LP64_DEBUG */
		return(0);
	}

	if (UIO_SEG_IS_USER_SPACE(a_uio->uio_segflg)) {
		return( 1 );
	}
	return( 0 );
}


/*
 * uio_create - create an uio_t.
 * 	Space is allocated to hold up to a_iovcount number of iovecs.  The uio_t
 *	is not fully initialized until all iovecs are added using uio_addiov calls.
 *	a_iovcount is the maximum number of iovecs you may add.
 */
uio_t uio_create( int a_iovcount,		/* number of iovecs */
				  off_t a_offset,		/* current offset */
				  int a_spacetype,		/* type of address space */
				  int a_iodirection )	/* read or write flag */
{
	void *				my_buf_p;
	int					my_size;
	uio_t				my_uio;
	
	my_size = sizeof(struct uio) + (sizeof(struct user_iovec) * a_iovcount);
	my_buf_p = kalloc(my_size);
	my_uio = uio_createwithbuffer( a_iovcount, 
									 a_offset,
									 a_spacetype,
									 a_iodirection,
									 my_buf_p,
									 my_size );
	if (my_uio != 0) {
		/* leave a note that we allocated this uio_t */
		my_uio->uio_flags |= UIO_FLAGS_WE_ALLOCED;
#if DEBUG
		hw_atomic_add(&uio_t_count, 1);
#endif
	}
	
	return( my_uio );
}


/*
 * uio_createwithbuffer - create an uio_t.
 * 	Create a uio_t using the given buffer.  The uio_t
 *	is not fully initialized until all iovecs are added using uio_addiov calls.
 *	a_iovcount is the maximum number of iovecs you may add.
 *	This call may fail if the given buffer is not large enough.
 */
__private_extern__ uio_t 
	uio_createwithbuffer( int a_iovcount,		/* number of iovecs */
				  			off_t a_offset,		/* current offset */
				  			int a_spacetype,	/* type of address space */
				 			int a_iodirection,	/* read or write flag */
				 			void *a_buf_p,		/* pointer to a uio_t buffer */
				 			int a_buffer_size )	/* size of uio_t buffer */
{
	uio_t				my_uio = (uio_t) a_buf_p;
	int					my_size;
	
	my_size = sizeof(struct uio) + (sizeof(struct user_iovec) * a_iovcount);
	if (a_buffer_size < my_size) {
#if DEBUG
		panic("%s :%d - a_buffer_size is too small\n", __FILE__, __LINE__); 
#endif /* DEBUG */
		return( NULL );
	}
	my_size = a_buffer_size;
	
#if DEBUG
	if (my_uio == 0) {
		panic("%s :%d - could not allocate uio_t\n", __FILE__, __LINE__); 
	}
	if (!IS_VALID_UIO_SEGFLG(a_spacetype)) {
		panic("%s :%d - invalid address space type\n", __FILE__, __LINE__); 
	}
	if (!(a_iodirection == UIO_READ || a_iodirection == UIO_WRITE)) {
		panic("%s :%d - invalid IO direction flag\n", __FILE__, __LINE__); 
	}
	if (a_iovcount > UIO_MAXIOV) {
		panic("%s :%d - invalid a_iovcount\n", __FILE__, __LINE__); 
	}
#endif /* DEBUG */

	bzero(my_uio, my_size);
	my_uio->uio_size = my_size;

	/* we use uio_segflg to indicate if the uio_t is the new format or */
	/* old (pre LP64 support) legacy format */
	switch (a_spacetype) {
	case UIO_USERSPACE:
		my_uio->uio_segflg = UIO_USERSPACE32;
	case UIO_SYSSPACE:
		my_uio->uio_segflg = UIO_SYSSPACE32;
	case UIO_PHYS_USERSPACE:
		my_uio->uio_segflg = UIO_PHYS_USERSPACE32;
	case UIO_PHYS_SYSSPACE:
		my_uio->uio_segflg = UIO_PHYS_SYSSPACE32;
	default:
		my_uio->uio_segflg = a_spacetype;
		break;
	}

	if (a_iovcount > 0) {
		my_uio->uio_iovs.uiovp = (struct user_iovec *)
			(((uint8_t *)my_uio) + sizeof(struct uio));
	}
	else {
		my_uio->uio_iovs.uiovp = NULL;
	}

	my_uio->uio_max_iovs = a_iovcount;
	my_uio->uio_offset = a_offset;
	my_uio->uio_rw = a_iodirection;
	my_uio->uio_flags = UIO_FLAGS_INITED;

	return( my_uio );
}

/*
 * uio_spacetype - return the address space type for the given uio_t
 */
int uio_spacetype( uio_t a_uio )
{
	if (a_uio == NULL) {
#if LP64_DEBUG
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
#endif /* LP64_DEBUG */
		return(-1);
	}

	return( a_uio->uio_segflg );
}

/*
 * uio_iovsaddr - get the address of the iovec array for the given uio_t.
 * This returns the location of the iovecs within the uio.
 * NOTE - for compatibility mode we just return the current value in uio_iovs
 * which will increase as the IO is completed and is NOT embedded within the
 * uio, it is a seperate array of one or more iovecs.
 */
struct user_iovec * uio_iovsaddr( uio_t a_uio )
{
	struct user_iovec *		my_addr;
	
	if (a_uio == NULL) {
		return(NULL);
	}
	
	if (a_uio->uio_segflg == UIO_USERSPACE || a_uio->uio_segflg == UIO_SYSSPACE) {
		/* we need this for compatibility mode. */
		my_addr = (struct user_iovec *) a_uio->uio_iovs.iovp;
	}
	else {
		my_addr = (struct user_iovec *) (((uint8_t *)a_uio) + sizeof(struct uio));
	}
	return(my_addr);
}

/*
 * uio_reset - reset an uio_t.
 * 	Reset the given uio_t to initial values.  The uio_t is not fully initialized
 * 	until all iovecs are added using uio_addiov calls.
 *	The a_iovcount value passed in the uio_create is the maximum number of 
 *	iovecs you may add.
 */
void uio_reset( uio_t a_uio,
				off_t a_offset,			/* current offset */
				int a_spacetype,		/* type of address space */
				int a_iodirection )		/* read or write flag */
{
	vm_size_t	my_size;
	int			my_max_iovs;
	u_int32_t	my_old_flags;
	
#if LP64_DEBUG
	if (a_uio == NULL) {
		panic("%s :%d - could not allocate uio_t\n", __FILE__, __LINE__); 
	}
	if (!IS_VALID_UIO_SEGFLG(a_spacetype)) {
		panic("%s :%d - invalid address space type\n", __FILE__, __LINE__); 
	}
	if (!(a_iodirection == UIO_READ || a_iodirection == UIO_WRITE)) {
		panic("%s :%d - invalid IO direction flag\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	if (a_uio == NULL) {
		return;
	}

	my_size = a_uio->uio_size;
	my_old_flags = a_uio->uio_flags;
	my_max_iovs = a_uio->uio_max_iovs;
	bzero(a_uio, my_size);
	a_uio->uio_size = my_size;
	a_uio->uio_segflg = a_spacetype;
	if (my_max_iovs > 0) {
		a_uio->uio_iovs.uiovp = (struct user_iovec *)
			(((uint8_t *)a_uio) + sizeof(struct uio));
	}
	else {
		a_uio->uio_iovs.uiovp = NULL;
	}
	a_uio->uio_max_iovs = my_max_iovs;
	a_uio->uio_offset = a_offset;
	a_uio->uio_rw = a_iodirection;
	a_uio->uio_flags = my_old_flags;

	return;
}

/*
 * uio_free - free a uio_t allocated via uio_init.  this also frees all
 * 	associated iovecs.
 */
void uio_free( uio_t a_uio ) 
{
#if DEBUG
	if (a_uio == NULL) {
		panic("%s :%d - passing NULL uio_t\n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	if (a_uio != NULL && (a_uio->uio_flags & UIO_FLAGS_WE_ALLOCED) != 0) {
#if DEBUG
		if ((int)(hw_atomic_sub(&uio_t_count, 1)) < 0) {
			panic("%s :%d - uio_t_count has gone negative\n", __FILE__, __LINE__); 
		}
#endif
		kfree(a_uio, a_uio->uio_size);
	}


}

/*
 * uio_addiov - add an iovec to the given uio_t.  You may call this up to
 * 	the a_iovcount number that was passed to uio_create.  This call will 
 * 	increment the residual IO count as iovecs are added to the uio_t.
 *	returns 0 if add was successful else non zero.
 */
int uio_addiov( uio_t a_uio, user_addr_t a_baseaddr, user_size_t a_length )
{
	int			i;
	
	if (a_uio == NULL) {
#if DEBUG
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
#endif /* LP64_DEBUG */
		return(-1);
	}

	if (UIO_IS_64_BIT_SPACE(a_uio)) {
		for ( i = 0; i < a_uio->uio_max_iovs; i++ ) {
			if (a_uio->uio_iovs.uiovp[i].iov_len == 0 && a_uio->uio_iovs.uiovp[i].iov_base == 0) {
				a_uio->uio_iovs.uiovp[i].iov_len = a_length;
				a_uio->uio_iovs.uiovp[i].iov_base = a_baseaddr;
				a_uio->uio_iovcnt++;
#if 1 // LP64todo - remove this temp workaround once we go live with uio KPI
				a_uio->uio_resid += a_length;
#else
				a_uio->uio_resid_64 += a_length;
#endif
				return( 0 );
			}
		}
	}
	else {
		for ( i = 0; i < a_uio->uio_max_iovs; i++ ) {
			if (a_uio->uio_iovs.kiovp[i].iov_len == 0 && a_uio->uio_iovs.kiovp[i].iov_base == 0) {
				a_uio->uio_iovs.kiovp[i].iov_len = (u_int32_t)a_length;
				a_uio->uio_iovs.kiovp[i].iov_base = (u_int32_t)((uintptr_t)a_baseaddr);
				a_uio->uio_iovcnt++;
				a_uio->uio_resid += a_length;
				return( 0 );
			}
		}
	}

	return( -1 );
}

/*
 * uio_getiov - get iovec data associated with the given uio_t.  Use
 *  a_index to iterate over each iovec (0 to (uio_iovcnt(uio_t) - 1)).
 *  a_baseaddr_p and a_length_p may be NULL.
 * 	returns -1 when a_index is >= uio_t.uio_iovcnt or invalid uio_t. 
 *	returns 0 when data is returned.
 */
int uio_getiov( uio_t a_uio, 
                 int a_index, 
                 user_addr_t * a_baseaddr_p, 
                 user_size_t * a_length_p )
{
	if (a_uio == NULL) {
#if DEBUG
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
#endif /* DEBUG */
		return(-1);
	}
    if ( a_index < 0 || a_index >= a_uio->uio_iovcnt) {
		return(-1);
    }

	if (UIO_IS_64_BIT_SPACE(a_uio)) {
        if (a_baseaddr_p != NULL) {
            *a_baseaddr_p = a_uio->uio_iovs.uiovp[a_index].iov_base;
        }
        if (a_length_p != NULL) {
            *a_length_p = a_uio->uio_iovs.uiovp[a_index].iov_len;
        }
	}
	else {
        if (a_baseaddr_p != NULL) {
            *a_baseaddr_p = a_uio->uio_iovs.kiovp[a_index].iov_base;
        }
        if (a_length_p != NULL) {
            *a_length_p = a_uio->uio_iovs.kiovp[a_index].iov_len;
        }
	}

    return( 0 );
}

/*
 * uio_calculateresid - runs through all iovecs associated with this
 *	uio_t and calculates (and sets) the residual IO count.
 */
__private_extern__ void uio_calculateresid( uio_t a_uio )
{
	int			i;
	
	if (a_uio == NULL) {
#if LP64_DEBUG
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
#endif /* LP64_DEBUG */
		return;
	}

	a_uio->uio_iovcnt = a_uio->uio_max_iovs;
	if (UIO_IS_64_BIT_SPACE(a_uio)) {
#if 1 // LP64todo - remove this temp workaround once we go live with uio KPI
		a_uio->uio_resid = 0;
#else
		a_uio->uio_resid_64 = 0;
#endif
		for ( i = 0; i < a_uio->uio_max_iovs; i++ ) {
			if (a_uio->uio_iovs.uiovp[i].iov_len != 0 && a_uio->uio_iovs.uiovp[i].iov_base != 0) {
#if 1 // LP64todo - remove this temp workaround once we go live with uio KPI
				a_uio->uio_resid += a_uio->uio_iovs.uiovp[i].iov_len;
#else
				a_uio->uio_resid_64 += a_uio->uio_iovs.uiovp[i].iov_len;
#endif
			}
		}

		/* position to first non zero length iovec (4235922) */
		while (a_uio->uio_iovcnt > 0 && a_uio->uio_iovs.uiovp->iov_len == 0) {
			a_uio->uio_iovcnt--;
			if (a_uio->uio_iovcnt > 0) {
				a_uio->uio_iovs.uiovp++;
			}
		}
	}
	else {
		a_uio->uio_resid = 0;
		for ( i = 0; i < a_uio->uio_max_iovs; i++ ) {
			if (a_uio->uio_iovs.kiovp[i].iov_len != 0 && a_uio->uio_iovs.kiovp[i].iov_base != 0) {
				a_uio->uio_resid += a_uio->uio_iovs.kiovp[i].iov_len;
			}
		}

		/* position to first non zero length iovec (4235922) */
		while (a_uio->uio_iovcnt > 0 && a_uio->uio_iovs.kiovp->iov_len == 0) {
			a_uio->uio_iovcnt--;
			if (a_uio->uio_iovcnt > 0) {
				a_uio->uio_iovs.kiovp++;
			}
		}
	}

	return;
}

/*
 * uio_update - update the given uio_t for a_count of completed IO.
 *	This call decrements the current iovec length and residual IO value
 *	and increments the current iovec base address and offset value. 
 *	If the current iovec length is 0 then advance to the next
 *	iovec (if any).
 * 	If the a_count passed in is 0, than only do the advancement
 *	over any 0 length iovec's.
 */
void uio_update( uio_t a_uio, user_size_t a_count )
{
#if LP64_DEBUG
	if (a_uio == NULL) {
		panic("%s :%d - invalid uio_t\n", __FILE__, __LINE__); 
	}
	if (UIO_IS_32_BIT_SPACE(a_uio) && a_count > 0xFFFFFFFFull) {
		panic("%s :%d - invalid count value \n", __FILE__, __LINE__); 
	}
#endif /* LP64_DEBUG */

	if (a_uio == NULL || a_uio->uio_iovcnt < 1) {
		return;
	}

	if (UIO_IS_64_BIT_SPACE(a_uio)) {
	        /*
		 * if a_count == 0, then we are asking to skip over
		 * any empty iovs
		 */
	        if (a_count) {
		        if (a_count > a_uio->uio_iovs.uiovp->iov_len) {
			        a_uio->uio_iovs.uiovp->iov_base += a_uio->uio_iovs.uiovp->iov_len;
				a_uio->uio_iovs.uiovp->iov_len = 0;
			}
			else {
			        a_uio->uio_iovs.uiovp->iov_base += a_count;
				a_uio->uio_iovs.uiovp->iov_len -= a_count;
			}
#if 1 // LP64todo - remove this temp workaround once we go live with uio KPI
			if (a_uio->uio_resid < 0) {
			        a_uio->uio_resid = 0;
			}
			if (a_count > (user_size_t)a_uio->uio_resid) {
			        a_uio->uio_offset += a_uio->uio_resid;
				a_uio->uio_resid = 0;
			}
			else {
			        a_uio->uio_offset += a_count;
				a_uio->uio_resid -= a_count;
			}
#else
			if (a_uio->uio_resid_64 < 0) {
			        a_uio->uio_resid_64 = 0;
			}
			if (a_count > (user_size_t)a_uio->uio_resid_64) {
			        a_uio->uio_offset += a_uio->uio_resid_64;
				a_uio->uio_resid_64 = 0;
			}
			else {
			        a_uio->uio_offset += a_count;
				a_uio->uio_resid_64 -= a_count;
			}
#endif // LP64todo
		}
		/*
		 * advance to next iovec if current one is totally consumed
		 */
		while (a_uio->uio_iovcnt > 0 && a_uio->uio_iovs.uiovp->iov_len == 0) {
			a_uio->uio_iovcnt--;
			if (a_uio->uio_iovcnt > 0) {
				a_uio->uio_iovs.uiovp++;
			}
		}
	}
	else {
	        /*
		 * if a_count == 0, then we are asking to skip over
		 * any empty iovs
		 */
	        if (a_count) {
		        if (a_count > a_uio->uio_iovs.kiovp->iov_len) {
			        a_uio->uio_iovs.kiovp->iov_base += a_uio->uio_iovs.kiovp->iov_len;
				a_uio->uio_iovs.kiovp->iov_len = 0;
			}
			else {
			        a_uio->uio_iovs.kiovp->iov_base += a_count;
				a_uio->uio_iovs.kiovp->iov_len -= a_count;
			}
			if (a_uio->uio_resid < 0) {
			        a_uio->uio_resid = 0;
			}
			if (a_count > (user_size_t)a_uio->uio_resid) {
			        a_uio->uio_offset += a_uio->uio_resid;
				a_uio->uio_resid = 0;
			}
			else {
			        a_uio->uio_offset += a_count;
				a_uio->uio_resid -= a_count;
			}
		}
		/*
		 * advance to next iovec if current one is totally consumed
		 */
		while (a_uio->uio_iovcnt > 0 && a_uio->uio_iovs.kiovp->iov_len == 0) {
			a_uio->uio_iovcnt--;
			if (a_uio->uio_iovcnt > 0) {
				a_uio->uio_iovs.kiovp++;
			}
		}
	}
	return;
}


/*
 * uio_duplicate - allocate a new uio and make a copy of the given uio_t.
 *	may return NULL.
 */
uio_t uio_duplicate( uio_t a_uio )
{
	uio_t		my_uio;
	int			i;

	if (a_uio == NULL) {
		return(NULL);
	}
	
	my_uio = (uio_t) kalloc(a_uio->uio_size);
	if (my_uio == 0) {
		panic("%s :%d - allocation failed\n", __FILE__, __LINE__); 
	}
	
	bcopy((void *)a_uio, (void *)my_uio, a_uio->uio_size);
	/* need to set our iovec pointer to point to first active iovec */
	if (my_uio->uio_max_iovs > 0) {
		my_uio->uio_iovs.uiovp = (struct user_iovec *)
			(((uint8_t *)my_uio) + sizeof(struct uio));

		/* advance to first nonzero iovec */
		if (my_uio->uio_iovcnt > 0) {
			for ( i = 0; i < my_uio->uio_max_iovs; i++ ) {
				if (UIO_IS_64_BIT_SPACE(a_uio)) {
					if (my_uio->uio_iovs.uiovp->iov_len != 0) {
						break;
					}
					my_uio->uio_iovs.uiovp++;
				}
				else {
					if (my_uio->uio_iovs.kiovp->iov_len != 0) {
						break;
					}
					my_uio->uio_iovs.kiovp++;
				}
			}
		}
	}

	return(my_uio);
}

