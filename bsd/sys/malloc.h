/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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
/* Copyright (c) 1998, 1999 Apple Computer, Inc. All Rights Reserved */
/* Copyright (c) 1995, 1997 Apple Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1987, 1993
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
 *	@(#)malloc.h	8.5 (Berkeley) 5/3/95
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#ifndef _SYS_MALLOC_H_
#define _SYS_MALLOC_H_

#include <sys/appleapiopts.h>


#ifdef KERNEL
/*
 * flags to malloc
 */
#define M_WAITOK        0x0000
#define M_NOWAIT        0x0001
#define M_ZERO          0x0004          /* bzero the allocation */
#define M_NULL          0x0008          /* return NULL if space is unavailable*/

#ifdef XNU_KERNEL_PRIVATE

#include <mach/vm_types.h>
#include <kern/kalloc.h>

ZONE_VIEW_DECLARE(ZV_NAMEI);

/*
 * Types of memory to be allocated (not all are used by us)
 */
#define M_DEVBUF        2       /* device driver memory */
#define M_PCB           4       /* protocol control block */
#define M_RTABLE        5       /* routing tables */
#define M_IFADDR        9       /* interface address */
#define M_SONAME        11      /* socket name */
#define M_PGRP          17      /* process group header */
#define M_FHANDLE       21      /* network file handle */
#define M_NFSNODE       24      /* NFS vnode private part */
#define M_VNODE         25      /* Dynamically allocated vnodes */
#define M_CACHE         26      /* Dynamically allocated cache entries */
#define M_DQUOT         27      /* UFS quota entries */
#define M_PROC_UUID_POLICY      28      /* proc UUID policy entries */
#define M_SHM           29      /* SVID compatible shared memory segments */
#define M_LOCKF         40      /* Byte-range locking structures */
#define M_PROC          41      /* Proc structures */
#define M_NETADDR       49      /* Export host address structure */
#define M_NFSSVC        50      /* NFS server structure */
#define M_NFSD          52      /* NFS server daemon structure */
#define M_IPMOPTS       53      /* internet multicast options */
#define M_IFMADDR       55      /* link-level multicast address */
#define M_NFSBIO        58      /* NFS client I/O buffers */
#define M_NFSBIGFH      61      /* NFS version 3 file handle */
#define M_TTYS          65      /* allocated tty structures */
#define M_OFILETABL     73      /* Open file descriptor table */
#define M_TEMP          80      /* misc temporary data buffers */
#define M_SECA          81      /* security associations, key management */
#define M_DEVFS         82
#define M_UDFNODE       84      /* UDF inodes */
#define M_UDFMNT        85      /* UDF mount structures */
#define M_IP6OPT        87      /* IPv6 options management */
#define M_KQUEUE        94      /* kqueue system */
#define M_KAUTH         100     /* kauth subsystem */
#define M_DUMMYNET      101     /* dummynet */
#define M_MACTEMP       104     /* MAC framework */
#define M_SBUF          105     /* string buffers */
#define M_SELECT        107     /* per-thread select memory */
#define M_INMFILTER     110     /* IPv4 multicast PCB-layer source filter */
#define M_IN6MFILTER    112     /* IPv6 multicast PCB-layer source filter */
#define M_IP6MOPTS      113     /* IPv6 multicast options */
#define M_IP6CGA        117
#define M_NECP          118     /* General NECP policy data */
#define M_FD_VN_DATA    122     /* Per fd vnode data */
#define M_FD_DIRBUF     123     /* Directory entries' buffer */
#define M_NETAGENT      124     /* Network Agents */
#define M_EVENTHANDLER  125     /* Eventhandler */
#define M_LLTABLE       126     /* Link layer table */
#define M_NWKWQ         127     /* Network work queue */
#define M_CFIL          128     /* Content Filter */

#define M_LAST          129     /* Must be last type + 1 */

#define MALLOC(space, cast, size, type, flags)                      \
	({ VM_ALLOC_SITE_STATIC(0, 0);                              \
	(space) = (cast)__MALLOC(size, type, flags, &site); })

#define REALLOC(space, cast, addr, size, type, flags)               \
	({ VM_ALLOC_SITE_STATIC(0, 0);                              \
	(space) = (cast)__REALLOC(addr, size, type, flags, &site); })

#define _MALLOC(size, type, flags)                                  \
	({ VM_ALLOC_SITE_STATIC(0, 0);                              \
	__MALLOC(size, type, flags, &site); })

#define _REALLOC(addr, size, type, flags)                           \
	({ VM_ALLOC_SITE_STATIC(0, 0);                              \
	__REALLOC(addr, size, type, flags, &site); })

#define _FREE(addr, type)                                           \
	(kheap_free_addr)(KHEAP_DEFAULT, addr)

#define FREE(addr, type)                                            \
	kheap_free_addr(KHEAP_DEFAULT, addr)

#pragma GCC visibility push(hidden)

extern void     *__MALLOC(
	size_t                size,
	int                   type,
	int                   flags,
	vm_allocation_site_t *site)  __attribute__((alloc_size(1)));

extern void     *__REALLOC(
	void                 *addr,
	size_t                size,
	int                   type,
	int                   flags,
	vm_allocation_site_t *site)  __attribute__((alloc_size(2)));

#pragma GCC visibility pop
#else /* XNU_KERNEL_PRIVATE */

#define M_PCB           4       /* protocol control block (smb) */
#define M_RTABLE        5       /* routing tables */
#define M_IFADDR        9       /* interface address (IOFireWireIP)*/
#define M_SONAME        11      /* socket name (smb) */
#define M_LOCKF         40      /* Byte-range locking structures (msdos) */
#define M_TEMP          80      /* misc temporary data buffers */
#define M_UDFNODE       84      /* UDF inodes (udf)*/
#define M_UDFMNT        85      /* UDF mount structures (udf)*/
#define M_KAUTH         100     /* kauth subsystem (smb) */

#define MALLOC(space, cast, size, type, flags) \
	(space) = (cast)_MALLOC(size, type, flags)

#define FREE(addr, type) \
	_FREE((void *)addr, type)

#define MALLOC_ZONE(space, cast, size, type, flags) \
	(space) = (cast)_MALLOC_ZONE(size, type, flags)

#define FREE_ZONE(addr, size, type) \
	_FREE_ZONE((void *)addr, size, type)

extern void     *_MALLOC(
	size_t          size,
	int             type,
	int             flags);

extern void     _FREE(
	void            *addr,
	int             type);

extern void     *_MALLOC_ZONE(
	size_t          size,
	int             type,
	int             flags);

extern void     _FREE_ZONE(
	void            *elem,
	size_t          size,
	int             type);

#endif /* !XNU_KERNEL_PRIVATE */

#endif  /* KERNEL */

#endif  /* _SYS_MALLOC_H_ */
