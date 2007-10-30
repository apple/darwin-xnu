/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1982, 1986, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department, and code derived from software contributed to
 * Berkeley by William Jolitz.
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
 * from: Utah $Hdr: mem.c 1.13 89/10/08$
 *	@(#)mem.c	8.1 (Berkeley) 6/11/93
 */

#include <mach_load.h>

/*
 * Memory special file
 */

#include <sys/param.h>
#include <sys/dir.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/vm.h>
#include <sys/uio_internal.h>
#include <sys/malloc.h>

#include <mach/vm_types.h>
#include <mach/vm_param.h>
#include <vm/vm_kern.h>		/* for kernel_map */

extern vm_offset_t kvtophys(vm_offset_t va); 
extern boolean_t kernacc(off_t, size_t );

static caddr_t devzerobuf;

int mmread(dev_t dev, struct uio *uio);
int mmwrite(dev_t dev, struct uio *uio);
int mmioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p);
int mmrw(dev_t dev, struct uio *uio, enum uio_rw rw);

int
mmread(dev_t dev, struct uio *uio)
{

	return (mmrw(dev, uio, UIO_READ));
}

int
mmwrite(dev_t dev, struct uio *uio)
{

	return (mmrw(dev, uio, UIO_WRITE));
}

int
mmioctl(__unused dev_t dev, u_long cmd, __unused caddr_t data, 
		__unused int flag, __unused struct proc *p)
{
	switch (cmd) {
	case FIONBIO:
	case FIOASYNC:
		/* OK to do nothing: we always return immediately */
		break;
	default:
		return ENODEV;
	}

	return (0);
}

int
mmrw(dev_t dev, struct uio *uio, enum uio_rw rw)
{
	register int o;
	register u_int c, v;
	int error = 0;
	vm_offset_t	where;
	vm_size_t size;

	while (uio_resid(uio) > 0 && error == 0) {
		if (uio_iov_len(uio) == 0) {
			uio_next_iov(uio);
			uio->uio_iovcnt--;
			if (uio->uio_iovcnt < 0)
				panic("mmrw");
			continue;
		}
		switch (minor(dev)) {

		/* minor device 0 is physical memory */
		case 0:
			v = trunc_page(uio->uio_offset);
			if (uio->uio_offset >= mem_size)
				goto fault;

			size= PAGE_SIZE;
			if (kmem_alloc(kernel_map, &where, size) 
				!= KERN_SUCCESS) {
				goto fault;
			}
			o = uio->uio_offset - v;
			// LP64todo - fix this!
			c = min(PAGE_SIZE - o, (u_int)uio_iov_len(uio));
			error = uiomove((caddr_t) (where + o), c, uio);
			kmem_free(kernel_map, where, PAGE_SIZE);
			continue;

		/* minor device 1 is kernel memory */
		case 1:
			/* Do some sanity checking */
			if (((vm_address_t)uio->uio_offset >= VM_MAX_KERNEL_ADDRESS) ||
				((vm_address_t)uio->uio_offset <= VM_MIN_KERNEL_ADDRESS))
				goto fault;
			c = uio_iov_len(uio);
			if (!kernacc(uio->uio_offset, c))
				goto fault;
			error = uiomove((caddr_t)(uintptr_t)uio->uio_offset,
					(int)c, uio);
			continue;

		/* minor device 2 is EOF/RATHOLE */
		case 2:
			if (rw == UIO_READ)
				return (0);
			c = uio_iov_len(uio);
			break;
		case 3:
			if(devzerobuf == NULL) {
				MALLOC(devzerobuf, caddr_t,PAGE_SIZE, M_TEMP, M_WAITOK);
				bzero(devzerobuf, PAGE_SIZE);
			}
			if(uio->uio_rw == UIO_WRITE) {
				c = uio_iov_len(uio);
				break;
			}
 			// LP64todo - fix this!
 			c = min(uio_iov_len(uio), PAGE_SIZE);
			error = uiomove(devzerobuf, (int)c, uio);
			continue;
		default:
			goto fault;
			break;
		}
			
		if (error)
			break;
		uio_iov_base_add(uio, c);
		uio_iov_len_add(uio, -((int)c));
		uio->uio_offset += c;
		uio_setresid(uio, (uio_resid(uio) - c));
	}
	return (error);
fault:
	return (EFAULT);
}


boolean_t
kernacc(
    off_t 	start,
    size_t	len
)
{
	off_t base;
	off_t end;
    
	base = trunc_page(start);
	end = start + len;
	
	while (base < end) {
	  if(kvtophys((vm_offset_t)base) == 0ULL)
			return(FALSE);
		base += page_size;
	}   

	return (TRUE);
}
