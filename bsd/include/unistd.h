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
 * Copyright (c) 1998-1999 Apple Computer, Inc. All Rights Reserved
 * Copyright (c) 1991, 1993, 1994
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
 *	@(#)unistd.h	8.12 (Berkeley) 4/27/95
 *
 *  Copyright (c)  1998 Apple Compter, Inc.
 *  All Rights Reserved
 */

/* History:
        7/14/99 EKN at Apple fixed getdirentriesattr from getdirentryattr
        3/26/98 CHW at Apple added real interface to searchfs call
  	3/5/98  CHW at Apple added hfs semantic system calls headers
*/

#ifndef _UNISTD_H_
#define	_UNISTD_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/unistd.h>

#define	 STDIN_FILENO	0	/* standard input file descriptor */
#define	STDOUT_FILENO	1	/* standard output file descriptor */
#define	STDERR_FILENO	2	/* standard error file descriptor */

#ifndef NULL
#define	NULL		0	/* null pointer constant */
#endif

#define _POSIX_THREADS		/* We support pthreads */

__BEGIN_DECLS
__dead void
	 _exit __P((int));
int	 access __P((const char *, int));
unsigned int	 alarm __P((unsigned int));
int	 chdir __P((const char *));
int	 chown __P((const char *, uid_t, gid_t));
int	 close __P((int));
size_t	 confstr __P((int, char *, size_t));
int	 dup __P((int));
int	 dup2 __P((int, int));
int	 execl __P((const char *, const char *, ...));
int	 execle __P((const char *, const char *, ...));
int	 execlp __P((const char *, const char *, ...));
int	 execv __P((const char *, char * const *));
int	 execve __P((const char *, char * const *, char * const *));
int	 execvp __P((const char *, char * const *));
pid_t	 fork __P((void));
long	 fpathconf __P((int, int));
char	*getcwd __P((char *, size_t));
gid_t	 getegid __P((void));
uid_t	 geteuid __P((void));
gid_t	 getgid __P((void));
int	 getgroups __P((int, gid_t []));
char	*getlogin __P((void));
pid_t	 getpgrp __P((void));
pid_t	 getpid __P((void));
pid_t	 getppid __P((void));
uid_t	 getuid __P((void));
int	 isatty __P((int));
int	 link __P((const char *, const char *));
off_t	 lseek __P((int, off_t, int));
long	 pathconf __P((const char *, int));
int	 pause __P((void));
int	 pipe __P((int *));
ssize_t	 read __P((int, void *, size_t));
int	 rmdir __P((const char *));
int	 setgid __P((gid_t));
int	 setpgid __P((pid_t, pid_t));
pid_t	 setsid __P((void));
int	 setuid __P((uid_t));
unsigned int	 sleep __P((unsigned int));
long	 sysconf __P((int));
pid_t	 tcgetpgrp __P((int));
int	 tcsetpgrp __P((int, pid_t));
char	*ttyname __P((int));
int	 unlink __P((const char *));
ssize_t	 write __P((int, const void *, size_t));

extern char *optarg;			/* getopt(3) external variables */
extern int optind, opterr, optopt, optreset;
int	 getopt __P((int, char * const [], const char *));

#ifndef	_POSIX_SOURCE
#ifdef	__STDC__
struct timeval;				/* select(2) */
#endif
int	 acct __P((const char *));
int	 async_daemon __P((void));
char	*brk __P((const char *));
int	 chroot __P((const char *));
char	*crypt __P((const char *, const char *));
int	 des_cipher __P((const char *, char *, long, int));
int	 des_setkey __P((const char *key));
int	 encrypt __P((char *, int));
void	 endusershell __P((void));
int	 exect __P((const char *, char * const *, char * const *));
int	 fchdir __P((int));
int	 fchown __P((int, int, int));
int	 fsync __P((int));
int	 ftruncate __P((int, off_t));
int	 getdtablesize __P((void));
int	 getgrouplist __P((const char *, int, int *, int *));
long	 gethostid __P((void));
int	 gethostname __P((char *, int));
mode_t	 getmode __P((const void *, mode_t));
__pure int
	 getpagesize __P((void));
char	*getpass __P((const char *));
char	*getusershell __P((void));
char	*getwd __P((char *));			/* obsoleted by getcwd() */
int	 initgroups __P((const char *, int));
int	 iruserok __P((unsigned long, int, const char *, const char *));
int	 mknod __P((const char *, mode_t, dev_t));
int	 mkstemp __P((char *));
char	*mktemp __P((char *));
int	 nfssvc __P((int, void *));
int	 nice __P((int));
#if 0
void	 psignal __P((unsigned int, const char *));
extern __const char *__const sys_siglist[];
#else
#include <signal.h>
#endif
int	 profil __P((char *, int, int, int));
int	 rcmd __P((char **, int, const char *,
		const char *, const char *, int *));
char	*re_comp __P((const char *));
int	 re_exec __P((const char *));
int	 readlink __P((const char *, char *, int));
int	 reboot __P((int));
int	 revoke __P((const char *));
int	 rresvport __P((int *));
int	 ruserok __P((const char *, int, const char *, const char *));
char	*sbrk __P((int));
int	 select __P((int, fd_set *, fd_set *, fd_set *, struct timeval *));
int	 setegid __P((gid_t));
int	 seteuid __P((uid_t));
int	 setgroups __P((int, const gid_t *));
void	 sethostid __P((long));
int	 sethostname __P((const char *, int));
int	 setkey __P((const char *));
int	 setlogin __P((const char *));
void	*setmode __P((const char *));
int	 setpgrp __P((pid_t pid, pid_t pgrp));	/* obsoleted by setpgid() */
int	 setregid __P((gid_t, gid_t));
int	 setreuid __P((uid_t, uid_t));
int	 setrgid __P((gid_t));
int	 setruid __P((uid_t));
void	 setusershell __P((void));
int	 swapon __P((const char *));
int	 symlink __P((const char *, const char *));
void	 sync __P((void));
int	 syscall __P((int, ...));
int	 truncate __P((const char *, off_t));
int	 ttyslot __P((void));
unsigned int	 ualarm __P((unsigned int, unsigned int));
int	 unwhiteout __P((const char *));
void	 usleep __P((unsigned int));
void	*valloc __P((size_t));			/* obsoleted by malloc() */
pid_t	 vfork __P((void));

extern char *suboptarg;			/* getsubopt(3) external variable */
int	 getsubopt __P((char **, char * const *, char **));

/*  HFS & HFS Plus semantics system calls go here */
int	getattrlist __P((const char*,void*,void*,size_t,unsigned long));
int	setattrlist __P((const char*,void*,void*,size_t,unsigned long));
int exchangedata __P((const char*,const char*,unsigned long));
int	checkuseraccess __P((const char*,uid_t,gid_t*,int,int,unsigned long));
int	getdirentriesattr __P((int,void*,void*,size_t,unsigned long*,unsigned long*,unsigned long*,unsigned long));
int	searchfs __P((const char*,void*,void*,unsigned long,unsigned long,void*));

int fsctl __P((const char *,unsigned long,void*,unsigned long));		


#endif /* !_POSIX_SOURCE */
__END_DECLS

#endif /* !_UNISTD_H_ */
