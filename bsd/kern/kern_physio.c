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
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/proc.h>

int
physio(strategy, bp, dev, flags, minphys, uio, blocksize)
	void (*strategy)(); 
	struct buf *bp;
	dev_t dev;
	int flags;
	u_int (*minphys)();
	struct uio *uio;
	int blocksize;
{
	struct iovec *iovp;
	struct proc *p = current_proc();
	int error, done, i, nobuf, s, todo;

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
		if(uio->uio_segflg != UIO_SYSSPACE) {
			if (!useracc(uio->uio_iov[i].iov_base,
				uio->uio_iov[i].iov_len,
		    		(flags == B_READ) ? B_WRITE : B_READ))
			return (EFAULT);
		}
	}
	/* Make sure we have a buffer, creating one if necessary. */
	if (nobuf = (bp == NULL)) {
//		bp = getphysbuf();
		panic("physio: null buf pointer\n");
		}

	/* [raise the processor priority level to splbio;] */
	s = splbio();

	/* [while the buffer is marked busy] */
	while (bp->b_flags & B_BUSY) {
		/* [mark the buffer wanted] */
		bp->b_flags |= B_WANTED;
		/* [wait until the buffer is available] */
		tsleep((caddr_t)bp, PRIBIO+1, "physbuf", 0);
	}

	/* Mark it busy, so nobody else will use it. */
	bp->b_flags |= B_BUSY;

	/* [lower the priority level] */
	splx(s);

	/* [set up the fixed part of the buffer for a transfer] */
	bp->b_dev = dev;
	bp->b_error = 0;
	bp->b_proc = p;

	/*
	 * [while there are data to transfer and no I/O error]
	 * Note that I/O errors are handled with a 'goto' at the bottom
	 * of the 'while' loop.
	 */
	for (i = 0; i < uio->uio_iovcnt; i++) {
		iovp = &uio->uio_iov[i];
		while (iovp->iov_len > 0) {
			/*
			 * [mark the buffer busy for physical I/O]
			 * (i.e. set B_PHYS (because it's an I/O to user
			 * memory, and B_RAW, because B_RAW is to be
			 * "Set by physio for raw transfers.", in addition
			 * to the "busy" and read/write flag.)
			 */
			s = splbio();
			bp->b_flags = B_BUSY | B_PHYS | B_RAW | flags;
			splx(s);

			/* [set up the buffer for a maximum-sized transfer] */
 			bp->b_blkno = uio->uio_offset / blocksize;
			bp->b_bcount = iovp->iov_len;
			bp->b_data = iovp->iov_base;
			
			/*
			 * [call minphys to bound the tranfer size]
			 * and remember the amount of data to transfer,
			 * for later comparison.
			 */
			(*minphys)(bp);
			todo = bp->b_bcount;

			/*
			 * [lock the part of the user address space involved
			 *    in the transfer]
			 * Beware vmapbuf(); it clobbers b_data and
			 * saves it in b_saveaddr.  However, vunmapbuf()
			 * restores it.
			 */

			if(uio->uio_segflg != UIO_SYSSPACE)
				vslock(bp->b_data, todo);
			
#if 0
			vmapbuf(bp, todo);
#endif /* 0 */
			/* [call strategy to start the transfer] */
			(*strategy)(bp);

			/*
			 * Note that the raise/wait/lower/get error
			 * steps below would be done by biowait(), but
			 * we want to unlock the address space before
			 * we lower the priority.
			 *
			 * [raise the priority level to splbio]
			 */
			s = splbio();

			/* [wait for the transfer to complete] */
			while ((bp->b_flags & B_DONE) == 0)
				tsleep((caddr_t) bp, PRIBIO + 1, "physio", 0);

			/*
			 * [unlock the part of the address space previously
			 *    locked]
			 */
#if 0
			vunmapbuf(bp, todo);
#endif /* 0 */
			if(uio->uio_segflg != UIO_SYSSPACE)
				vsunlock(bp->b_data, todo);

			/* remember error value (save a splbio/splx pair) */
			if (bp->b_flags & B_ERROR)
				error = (bp->b_error ? bp->b_error : EIO);

			/* [lower the priority level] */
			splx(s);

			/*
			 * [deduct the transfer size from the total number
			 *    of data to transfer]
			 */
			done = bp->b_bcount - bp->b_resid;
			iovp->iov_len -= done;
                        iovp->iov_base += done;
                        uio->uio_offset += done;
                        uio->uio_resid -= done;

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
	s = splbio();
	bp->b_flags &= ~(B_BUSY | B_PHYS | B_RAW);
#if 0
	if (nobuf)
		putphysbuf(bp);

	else 
#endif /* 0 */
		{
		/*
		 * [if another process is waiting for the raw I/O buffer,
		 *    wake up processes waiting to do physical I/O;
		 */
		if (bp->b_flags & B_WANTED) {
			bp->b_flags &= ~B_WANTED;
			wakeup(bp);
		}
	}
	splx(s);

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

	bp->b_bcount = min(MAXPHYS, bp->b_bcount);
        return bp->b_bcount;
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
