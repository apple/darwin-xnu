/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/*-
 * Copyright (c) 1982, 1986, 1993
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
 *	@(#)mman.h	8.1 (Berkeley) 6/2/93
 */

#ifndef	_SYS_MMAN_H_
#define _SYS_MMAN_H_

#include <sys/appleapiopts.h>
#include <mach/shared_memory_server.h>

/*
 * Protections are chosen from these bits, or-ed together
 */
#define	PROT_NONE	0x00	/* no permissions */
#define	PROT_READ	0x01	/* pages can be read */
#define	PROT_WRITE	0x02	/* pages can be written */
#define	PROT_EXEC	0x04	/* pages can be executed */

/*
 * Flags contain sharing type and options.
 * Sharing types; choose one.
 */
#define	MAP_SHARED	0x0001		/* share changes */
#define	MAP_PRIVATE	0x0002		/* changes are private */
#define	MAP_COPY	MAP_PRIVATE	/* Obsolete */

/*
 * Other flags
 */
#define	MAP_FIXED	 0x0010	/* map addr must be exactly as requested */
#define	MAP_RENAME	 0x0020	/* Sun: rename private pages to file */
#define	MAP_NORESERVE	 0x0040	/* Sun: don't reserve needed swap area */
#define	MAP_RESERVED0080 0x0080	/* previously unimplemented MAP_INHERIT */
#define	MAP_NOEXTEND	 0x0100	/* for MAP_FILE, don't change file size */
#define	MAP_HASSEMAPHORE 0x0200	/* region may contain semaphores */

#ifdef _P1003_1B_VISIBLE
/*
 * Process memory locking
 */
#define MCL_CURRENT	0x0001	/* Lock only current memory */
#define MCL_FUTURE	0x0002	/* Lock all future memory as well */

#endif /* _P1003_1B_VISIBLE */

/*
 * Error return from mmap()
 */
#define MAP_FAILED	((void *)-1)

/*
 * msync() flags
 */
#define	MS_SYNC		0x0000	/* msync synchronously */
#define MS_ASYNC	0x0001	/* return immediately */
#define MS_INVALIDATE	0x0002	/* invalidate all cached data */

#ifndef _POSIX_SOURCE
#define MS_KILLPAGES    0x0004  /* invalidate pages, leave mapped */
#define MS_DEACTIVATE   0x0008  /* deactivate pages, leave mapped */
#endif

/*
 * Mapping type
 */
#define	MAP_FILE	0x0000	/* map from file (default) */
#define	MAP_ANON	0x1000	/* allocated from memory, swap space */

/*
 * Advice to madvise
 */
#define	MADV_NORMAL	0	/* no further special treatment */
#define	MADV_RANDOM	1	/* expect random page references */
#define	MADV_SEQUENTIAL	2	/* expect sequential page references */
#define	MADV_WILLNEED	3	/* will need these pages */
#define	MADV_DONTNEED	4	/* dont need these pages */
#define	MADV_FREE	5	/* dont need these pages, and junk contents */
#define	POSIX_MADV_NORMAL	MADV_NORMAL
#define	POSIX_MADV_RANDOM	MADV_RANDOM
#define	POSIX_MADV_SEQUENTIAL	MADV_SEQUENTIAL
#define	POSIX_MADV_WILLNEED	MADV_WILLNEED
#define	POSIX_MADV_DONTNEED	MADV_DONTNEED

/*
 * Return bits from mincore
 */
#define	MINCORE_INCORE	 	 0x1 /* Page is incore */
#define	MINCORE_REFERENCED	 0x2 /* Page has been referenced by us */
#define	MINCORE_MODIFIED	 0x4 /* Page has been modified by us */
#define	MINCORE_REFERENCED_OTHER 0x8 /* Page has been referenced */
#define	MINCORE_MODIFIED_OTHER	0x10 /* Page has been modified */

#ifndef KERNEL

#include <sys/cdefs.h>

__BEGIN_DECLS
#ifdef _P1003_1B_VISIBLE
int	mlockall __P((int));
int	munlockall __P((void));
#endif /* _P1003_1B_VISIBLE */
int	mlock __P((const void *, size_t));
#ifndef _MMAP_DECLARED
#define	_MMAP_DECLARED
void *	mmap __P((void *, size_t, int, int, int, off_t));
#endif
int	mprotect __P((const void *, size_t, int));
int	msync __P((void *, size_t, int));
int	munlock __P((const void *, size_t));
int	munmap __P((void *, size_t));
int	shm_open __P((const char *, int, ...));
int	shm_unlink __P((const char *));
int	posix_madvise __P((void *, size_t, int));
#ifndef _POSIX_SOURCE
#ifdef __APPLE_API_PRIVATE
int	load_shared_file __P((char *, caddr_t, u_long,
		caddr_t *, int, sf_mapping_t *, int *));
int	reset_shared_file __P((caddr_t *, int, sf_mapping_t *));
int	new_system_shared_regions __P((void));
#endif /* __APPLE_API_PRIVATE */
int	madvise __P((void *, size_t, int));
int	mincore __P((const void *, size_t, char *));
int	minherit __P((void *, size_t, int));
#endif
__END_DECLS

#endif /* !KERNEL */
#endif /* !_SYS_MMAN_H_ */
