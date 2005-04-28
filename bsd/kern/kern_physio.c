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
/*-
 * Copyright (c) 1982, 1986, 1990, 1993
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
 *	from: @(#)kern_physio.c	8.1 (Berkeley) 6/10/93
 */
/*
 * HISTORY
 * 27-July-97  Umesh Vaishampayan  (umeshv@apple.com)
 *	Allow physio() to kernel space.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf_internal.h>
#include <sys/conf.h>
#include <sys/proc_internal.h>
#include <sys/uio_internal.h>

int
physio(strategy, bp, dev, flags, minphys, uio, blocksize)
	void (*strategy)(); 
	buf_t bp;
	dev_t dev;
	int flags;
	u_int (*minphys)();
	struct uio *uio;
	int blocksize;
{
	struct proc *p = current_proc();
	int error, i, nobuf, todo, iosize;
#if LP64KERN
	int64_t done;
#else
	int done;
#endif

	error = 0;
	flags &= B_READ | B_WRITE;

	/*
	 * [check user read/write access to the data buffer]
	 *
	 * Check each iov one by one.  Note that we know if we're reading or
	 * writing, so we ignore the uio's rw parameter.  Also note that if
	 * we're doing a read, that's a *write* to user-space.
	 */
	for (i = 0; i < uio->uio_iovcnt; i++) {
		if(UIO_SEG_IS_USER_SPACE(uio->uio_segflg)) {
			if (!useracc(uio_iov_base_at(uio, i),
					uio_iov_len_at(uio, i),
		    		(flags == B_READ) ? B_WRITE : B_READ))
			return (EFAULT);
		}
	}
	/* Make sure we have a buffer, creating one if necessary. */
	if (nobuf = (bp == NULL)) {
			bp = buf_alloc((vnode_t)0);
		}

	/* [while the buffer is marked busy] */
	while (((error = (int)buf_acquire(bp, 0, 0, 0)) == EAGAIN));
	
	if (error) {
			if (nobuf)
				buf_free(bp);
	        return (error);
	}

	/* [set up the fixed part of the buffer for a transfer] */
	bp->b_dev = dev;
	bp->b_proc = p;

	buf_seterror(bp, 0);
	/*
	 * [while there is data to transfer and no I/O error]
	 * Note that I/O errors are handled with a 'goto' at the bottom
	 * of the 'while' loop.
	 */
	for (i = 0; i < uio->uio_iovcnt; i++) {
		while (uio_iov_len_at(uio, i) > 0) {
			/*
			 * [mark the buffer busy for physical I/O]
			 * (i.e. set B_PHYS (because it's an I/O to user
			 * memory, and B_RAW, because B_RAW is to be
			 * "Set by physio for raw transfers.", in addition
			 * to the read/write flag.)
			 */
		        buf_setflags(bp, B_PHYS | B_RAW | flags);
			
			if ( (iosize = uio_iov_len_at(uio, i)) > MAXPHYSIO_WIRED)
			        iosize = MAXPHYSIO_WIRED;

			/* [set up the buffer for a maximum-sized transfer] */
 			buf_setblkno(bp, uio->uio_offset / blocksize);
			buf_setcount(bp, iosize);
			// LP64todo - fix this!
			buf_setdataptr(bp, CAST_DOWN(caddr_t, uio_iov_base_at(uio, i)));
			
			/*
			 * [call minphys to bound the tranfer size]
			 * and remember the amount of data to transfer,
			 * for later comparison.
			 */
			(*minphys)(bp);
			todo = buf_count(bp);

			/*
			 * [lock the part of the user address space involved
			 *    in the transfer]
			 */

			if(UIO_SEG_IS_USER_SPACE(uio->uio_segflg))
				vslock(CAST_USER_ADDR_T(buf_dataptr(bp)),
				       (user_size_t)todo);
			
			/* [call strategy to start the transfer] */
			(*strategy)(bp);


			/* [wait for the transfer to complete] */
			error = (int)buf_biowait(bp);

			/*
			 * [unlock the part of the address space previously
			 *    locked]
			 */
			if(UIO_SEG_IS_USER_SPACE(uio->uio_segflg))
				vsunlock(CAST_USER_ADDR_T(buf_dataptr(bp)),
					 (user_size_t)todo,
					 (flags & B_READ));

			/*
			 * [deduct the transfer size from the total number
			 *    of data to transfer]
			 */
			done = buf_count(bp) - buf_resid(bp);
			uio_iov_len_add_at(uio, -done, i);
			uio_iov_base_add_at(uio, done, i);
			uio->uio_offset += done;
			uio_setresid(uio, (uio_resid(uio) - done));

			/*
			 * Now, check for an error.
			 * Also, handle weird end-of-disk semantics.
			 */
			if (error || done < todo)
				goto done;
		}
	}

done:
	/*
	 * [clean up the state of the buffer]
	 * Remember if somebody wants it, so we can wake them up below.
	 * Also, if we had to steal it, give it back.
	 */

	buf_clearflags(bp, B_PHYS | B_RAW);
	if (nobuf)
		buf_free(bp);
	else 
	        {
		        buf_drop(bp);
		}

	return (error);
}

/*
 * Leffler, et al., says on p. 231:
 * "The minphys() routine is called by physio() to adjust the
 * size of each I/O transfer before the latter is passed to
 * the strategy routine..." 
 *
 * so, just adjust the buffer's count accounting to MAXPHYS here,
 * and return the new count;
 */
u_int
minphys(bp)
	struct buf *bp;
{

	buf_setcount(bp, min(MAXPHYS, buf_count(bp)));
        return buf_count(bp);
}

/*
 * Do a read on a device for a user process.
 */
rawread(dev, uio)
	dev_t dev;
	struct uio *uio;
{
	return (physio(cdevsw[major(dev)].d_strategy, (struct buf *)NULL,
	    dev, B_READ, minphys, uio, DEV_BSIZE));
}

/*
 * Do a write on a device for a user process.
 */
rawwrite(dev, uio)
	dev_t dev;
	struct uio *uio;
{
	return (physio(cdevsw[major(dev)].d_strategy, (struct buf *)NULL,
	    dev, B_WRITE, minphys, uio, DEV_BSIZE));
}
