/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Robert Elz at The University of Melbourne.
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
 *	@(#)quota.h	8.3 (Berkeley) 8/19/94
 */

#ifndef _UFS_QUOTA_H
#define _UFS_QUOTA_H

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
#include <sys/quota.h>

#ifdef KERNEL
#include <sys/queue.h>


#include <sys/cdefs.h>

struct inode;
struct mount;
struct proc;
struct ucred;
__BEGIN_DECLS
int	chkdq __P((struct inode *, int64_t, struct ucred *, int));
int	chkdqchg __P((struct inode *, int64_t, struct ucred *, int));
int	chkiq __P((struct inode *, long, struct ucred *, int));
int	chkiqchg __P((struct inode *, long, struct ucred *, int));
int	getinoquota __P((struct inode *));
int	getquota __P((struct mount *, u_long, int, caddr_t));
int	qsync __P((struct mount *mp));
int	quotaoff __P((struct proc *, struct mount *, int));
int	quotaon __P((struct proc *, struct mount *, int, caddr_t, enum uio_seg));
int	setquota __P((struct mount *, u_long, int, caddr_t));
int	setuse __P((struct mount *, u_long, int, caddr_t));
int	ufs_quotactl __P((struct mount *, int, uid_t, caddr_t, struct proc *));
__END_DECLS

#if DIAGNOSTIC
__BEGIN_DECLS
void	chkdquot __P((struct inode *));
__END_DECLS
#endif
#endif /* KERNEL */

#endif /* __APPLE_API_PRIVATE */
#endif /* ! _UFS_QUOTA_H */
