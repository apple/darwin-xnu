/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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

/*	(c) 1997-1998	Apple Computer, Inc.  All Rights Reserved */
/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Scooter Morris at Genentech Inc.
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
 *
 *	@(#)hfs_lockf.h	1.0 5/5/98
 *	derived from @(#)lockf.h	8.2 (Berkeley) 10/26/94
 */

/*
 * The hfslockf structure is a kernel structure which contains the information
 * associated with a byte range lock.  The hfslockf structures are linked into
 * the inode structure. Locks are sorted by the starting byte of the lock for
 * efficiency.
 */
TAILQ_HEAD(locklist, hfslockf);

struct hfslockf {
	short	lf_flags;	    /* Semantics: F_POSIX, F_FLOCK, F_WAIT */
	short	lf_type;	    /* Lock type: F_RDLCK, F_WRLCK */
	off_t	lf_start;	    /* Byte # of the start of the lock */
	off_t	lf_end;		    /* Byte # of the end of the lock (-1=EOF) */
	caddr_t	lf_id;		    /* Id of the resource holding the lock */
    struct	hfsnode *lf_hfsnode;    /* Back pointer to the inode */
	struct	hfslockf *lf_next;	    /* Pointer to the next lock on this inode */
	struct	locklist lf_blkhd;  /* List of requests blocked on this lock */
	TAILQ_ENTRY(hfslockf) lf_block;/* A request waiting for a lock */
};

/* Maximum length of sleep chains to traverse to try and detect deadlock. */
#define MAXDEPTH 50

__BEGIN_DECLS
void	 hfs_addblock __P((struct hfslockf *, struct hfslockf *));
int	 hfs_clearlock __P((struct hfslockf *));
int	 hfs_findoverlap __P((struct hfslockf *,
	    struct hfslockf *, int, struct hfslockf ***, struct hfslockf **));
struct hfslockf *
	 hfs_getblock __P((struct hfslockf *));
int	 hfs_getlock __P((struct hfslockf *, struct flock *));
int	 hfs_setlock __P((struct hfslockf *));
void	 hfs_split __P((struct hfslockf *, struct hfslockf *));
void	 hfs_wakelock __P((struct hfslockf *));
__END_DECLS

#ifdef LOCKF_DEBUG
extern int lockf_debug;

__BEGIN_DECLS
void	hfs_lprint __P((char *, struct hfslockf *));
void	hfs_lprintlist __P((char *, struct hfslockf *));
__END_DECLS
#endif
