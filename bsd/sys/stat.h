/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	@(#)stat.h	8.9 (Berkeley) 8/17/94
 */


#ifndef _SYS_STAT_H_
#define	_SYS_STAT_H_

#include <sys/_types.h>
#include <sys/cdefs.h>

/*
 * [XSI] The blkcnt_t, blksize_t, dev_t, ino_t, mode_t, nlink_t, uid_t,
 * gid_t, off_t, and time_t types shall be defined as described in
 * <sys/types.h>.
 */
#ifndef _BLKCNT_T
typedef	__darwin_blkcnt_t	blkcnt_t;
#define	_BLKCNT_T
#endif

#ifndef _BLKSIZE_T
typedef	__darwin_blksize_t	blksize_t;
#define	_BLKSIZE_T
#endif

#ifndef _DEV_T
typedef	__darwin_dev_t		dev_t;		/* device number */
#define _DEV_T
#endif

#ifndef	_INO_T
typedef	__darwin_ino_t		ino_t;		/* inode number */
#define _INO_T
#endif

#ifndef	_MODE_T
typedef	__darwin_mode_t		mode_t;
#define _MODE_T
#endif

#ifndef _NLINK_T
typedef	__uint16_t		nlink_t;	/* link count */
#define	_NLINK_T
#endif

#ifndef _UID_T
typedef __darwin_uid_t		uid_t;		/* user id */
#define _UID_T
#endif

#ifndef _GID_T
typedef __darwin_gid_t		gid_t;
#define _GID_T
#endif

#ifndef _OFF_T
typedef __darwin_off_t		off_t;
#define _OFF_T
#endif

#ifndef	_TIME_T
#define	_TIME_T
typedef	__darwin_time_t		time_t;
#endif


/* [XSI] The timespec structure may be defined as described in <time.h> */
#ifndef _TIMESPEC
#define _TIMESPEC
struct timespec {
	time_t	tv_sec;		/* seconds */
	long	tv_nsec;	/* and nanoseconds */
};

// LP64todo - should this move?
#ifdef KERNEL
/* LP64 version of struct timespec.  time_t is a long and must grow when 
 * we're dealing with a 64-bit process.
 * WARNING - keep in sync with struct timespec
 */
struct user_timespec {
	user_time_t	tv_sec;		/* seconds */
	int32_t	tv_nsec __attribute((aligned(8)));	/* and nanoseconds */
};
#endif // KERNEL
#endif	/* _TIMESPEC */


#ifndef _POSIX_C_SOURCE
/*
 * XXX So deprecated, it would make your head spin
 *
 * The old stat structure.  In fact, this is not used by the kernel at all,
 * and should not be used by user space, and should be removed from this
 * header file entirely (along with the unused cvtstat() prototype in
 * vnode_internal.h).
 */
struct ostat {
	__uint16_t	st_dev;		/* inode's device */
	ino_t		st_ino;		/* inode's number */
	mode_t		st_mode;	/* inode protection mode */
	nlink_t		st_nlink;	/* number of hard links */
	__uint16_t	st_uid;		/* user ID of the file's owner */
	__uint16_t	st_gid;		/* group ID of the file's group */
	__uint16_t	st_rdev;	/* device type */
	__int32_t	st_size;	/* file size, in bytes */
	struct	timespec st_atimespec;	/* time of last access */
	struct	timespec st_mtimespec;	/* time of last data modification */
	struct	timespec st_ctimespec;	/* time of last file status change */
	__int32_t	st_blksize;	/* optimal blocksize for I/O */
	__int32_t	st_blocks;	/* blocks allocated for file */
	__uint32_t	st_flags;	/* user defined flags for file */
	__uint32_t	st_gen;		/* file generation number */
};
#endif /* !_POSIX_C_SOURCE */

/*
 * [XSI] This structure is used as the second parameter to the fstat(),
 * lstat(), and stat() functions.
 */
struct stat {
	dev_t	 	st_dev;		/* [XSI] ID of device containing file */
	ino_t	  	st_ino;		/* [XSI] File serial number */
	mode_t	 	st_mode;	/* [XSI] Mode of file (see below) */
	nlink_t		st_nlink;	/* [XSI] Number of hard links */
	uid_t		st_uid;		/* [XSI] User ID of the file */
	gid_t		st_gid;		/* [XSI] Group ID of the file */
	dev_t		st_rdev;	/* [XSI] Device ID */
#ifndef _POSIX_C_SOURCE
	struct	timespec st_atimespec;	/* time of last access */
	struct	timespec st_mtimespec;	/* time of last data modification */
	struct	timespec st_ctimespec;	/* time of last status change */
#else
	time_t		st_atime;	/* [XSI] Time of last access */
	long		st_atimensec;	/* nsec of last access */
	time_t		st_mtime;	/* [XSI] Last data modification time */
	long		st_mtimensec;	/* last data modification nsec */
	time_t		st_ctime;	/* [XSI] Time of last status change */
	long		st_ctimensec;	/* nsec of last status change */
#endif
	off_t		st_size;	/* [XSI] file size, in bytes */
	blkcnt_t	st_blocks;	/* [XSI] blocks allocated for file */
	blksize_t	st_blksize;	/* [XSI] optimal blocksize for I/O */
	__uint32_t	st_flags;	/* user defined flags for file */
	__uint32_t	st_gen;		/* file generation number */
	__int32_t	st_lspare;	/* RESERVED: DO NOT USE! */
	__int64_t	st_qspare[2];	/* RESERVED: DO NOT USE! */
};

// LP64todo - should this move?
#ifdef KERNEL
#include <machine/types.h>

/* LP64 version of struct stat.  time_t (see timespec) is a long and must 
 * grow when we're dealing with a 64-bit process.
 * WARNING - keep in sync with struct stat
 */

struct user_stat {
	dev_t	 	st_dev;		/* [XSI] ID of device containing file */
	ino_t	  	st_ino;		/* [XSI] File serial number */
	mode_t	 	st_mode;	/* [XSI] Mode of file (see below) */
	nlink_t		st_nlink;	/* [XSI] Number of hard links */
	uid_t		st_uid;		/* [XSI] User ID of the file */
	gid_t		st_gid;		/* [XSI] Group ID of the file */
	dev_t		st_rdev;	/* [XSI] Device ID */
#ifndef _POSIX_C_SOURCE
	struct	user_timespec st_atimespec; /* time of last access */
	struct	user_timespec st_mtimespec; /* time of last data modification */
	struct	user_timespec st_ctimespec; /* time of last status change */
#else
	user_time_t	st_atime;	/* [XSI] Time of last access */
	__int64_t	st_atimensec;	/* nsec of last access */
	user_time_t	st_mtime;	/* [XSI] Last data modification */
	__int64_t	st_mtimensec;	/* last data modification nsec */
	user_time_t	st_ctime;	/* [XSI] Time of last status change */
	__int64_t	st_ctimensec;	/* nsec of last status change */
#endif
	off_t		st_size;	/* [XSI] File size, in bytes */
	blkcnt_t	st_blocks;	/* [XSI] Blocks allocated for file */
	blksize_t	st_blksize;	/* [XSI] Optimal blocksize for I/O */
	__uint32_t	st_flags;	/* user defined flags for file */
	__uint32_t	st_gen;		/* file generation number */
	__int32_t	st_lspare;	/* RESERVED: DO NOT USE! */
	__int64_t	st_qspare[2];	/* RESERVED: DO NOT USE! */
};

extern void munge_stat(struct stat *sbp, struct user_stat *usbp);

#endif // KERNEL


#ifndef _POSIX_C_SOURCE
#define st_atime st_atimespec.tv_sec
#define st_mtime st_mtimespec.tv_sec
#define st_ctime st_ctimespec.tv_sec
#endif

/*
 * [XSI] The following are symbolic names for the values of type mode_t.  They
 * are bitmap values.
 */
#ifndef S_IFMT
/* File type */
#define	S_IFMT		0170000		/* [XSI] type of file mask */
#define	S_IFIFO		0010000		/* [XSI] named pipe (fifo) */
#define	S_IFCHR		0020000		/* [XSI] character special */
#define	S_IFDIR		0040000		/* [XSI] directory */
#define	S_IFBLK		0060000		/* [XSI] block special */
#define	S_IFREG		0100000		/* [XSI] regular */
#define	S_IFLNK		0120000		/* [XSI] symbolic link */
#define	S_IFSOCK	0140000		/* [XSI] socket */
#ifndef _POSIX_C_SOURCE
#define	S_IFWHT		0160000		/* whiteout */
#define S_IFXATTR	0200000		/* extended attribute */
#endif

/* File mode */
/* Read, write, execute/search by owner */
#define	S_IRWXU		0000700		/* [XSI] RWX mask for owner */
#define	S_IRUSR		0000400		/* [XSI] R for owner */
#define	S_IWUSR		0000200		/* [XSI] W for owner */
#define	S_IXUSR		0000100		/* [XSI] X for owner */
/* Read, write, execute/search by group */
#define	S_IRWXG		0000070		/* [XSI] RWX mask for group */
#define	S_IRGRP		0000040		/* [XSI] R for group */
#define	S_IWGRP		0000020		/* [XSI] W for group */
#define	S_IXGRP		0000010		/* [XSI] X for group */
/* Read, write, execute/search by others */
#define	S_IRWXO		0000007		/* [XSI] RWX mask for other */
#define	S_IROTH		0000004		/* [XSI] R for other */
#define	S_IWOTH		0000002		/* [XSI] W for other */
#define	S_IXOTH		0000001		/* [XSI] X for other */

#define	S_ISUID		0004000		/* [XSI] set user id on execution */
#define	S_ISGID		0002000		/* [XSI] set group id on execution */
#define	S_ISVTX		0001000		/* [XSI] directory restrcted delete */

#ifndef _POSIX_C_SOURCE
#define	S_ISTXT		S_ISVTX		/* sticky bit: not supported */
#define	S_IREAD		S_IRUSR		/* backward compatability */
#define	S_IWRITE	S_IWUSR		/* backward compatability */
#define	S_IEXEC		S_IXUSR		/* backward compatability */
#endif
#endif	/* !S_IFMT */

/*
 * [XSI] The following macros shall be provided to test whether a file is
 * of the specified type.  The value m supplied to the macros is the value
 * of st_mode from a stat structure.  The macro shall evaluate to a non-zero
 * value if the test is true; 0 if the test is false.
 */
#define	S_ISBLK(m)	(((m) & 0170000) == 0060000)	/* block special */
#define	S_ISCHR(m)	(((m) & 0170000) == 0020000)	/* char special */
#define	S_ISDIR(m)	(((m) & 0170000) == 0040000)	/* directory */
#define	S_ISFIFO(m)	(((m) & 0170000) == 0010000)	/* fifo or socket */
#define	S_ISREG(m)	(((m) & 0170000) == 0100000)	/* regular file */
#define	S_ISLNK(m)	(((m) & 0170000) == 0120000)	/* symbolic link */
#define	S_ISSOCK(m)	(((m) & 0170000) == 0140000)	/* socket */
#ifndef _POSIX_C_SOURCE
#define	S_ISWHT(m)	(((m) & 0170000) == 0160000)	/* whiteout */
#define S_ISXATTR(m)	(((m) & 0200000) == 0200000)	/* extended attribute */
#endif

/*
 * [XSI] The implementation may implement message queues, semaphores, or
 * shared memory objects as distinct file types.  The following macros
 * shall be provided to test whether a file is of the specified type.
 * The value of the buf argument supplied to the macros is a pointer to
 * a stat structure.  The macro shall evaluate to a non-zero value if
 * the specified object is implemented as a distinct file type and the
 * specified file type is contained in the stat structure referenced by
 * buf.  Otherwise, the macro shall evaluate to zero.
 *
 * NOTE:	The current implementation does not do this, although
 *		this may change in future revisions, and co currently only
 *		provides these macros to ensure source compatability with
 *		implementations which do.
 */
#define	S_TYPEISMQ(buf)		(0)	/* Test for a message queue */
#define	S_TYPEISSEM(buf)	(0)	/* Test for a semaphore */
#define	S_TYPEISSHM(buf)	(0)	/* Test for a shared memory object */

/*
 * [TYM] The implementation may implement typed memory objects as distinct
 * file types, and the following macro shall test whether a file is of the
 * specified type.  The value of the buf argument supplied to the macros is
 * a pointer to a stat structure.  The macro shall evaluate to a non-zero
 * value if the specified object is implemented as a distinct file type and
 * the specified file type is contained in the stat structure referenced by
 * buf.  Otherwise, the macro shall evaluate to zero.
 *
 * NOTE:	The current implementation does not do this, although
 *		this may change in future revisions, and co currently only
 *		provides this macro to ensure source compatability with
 *		implementations which do.
 */
#define	S_TYPEISTMO(buf)	(0)	/* Test for a typed memory object */


#ifndef _POSIX_C_SOURCE
#define	ACCESSPERMS	(S_IRWXU|S_IRWXG|S_IRWXO)	/* 0777 */
							/* 7777 */
#define	ALLPERMS	(S_ISUID|S_ISGID|S_ISTXT|S_IRWXU|S_IRWXG|S_IRWXO)
							/* 0666 */
#define	DEFFILEMODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)

#define S_BLKSIZE	512		/* block size used in the stat struct */

/*
 * Definitions of flags stored in file flags word.
 *
 * Super-user and owner changeable flags.
 */
#define	UF_SETTABLE	0x0000ffff	/* mask of owner changeable flags */
#define	UF_NODUMP	0x00000001	/* do not dump file */
#define	UF_IMMUTABLE	0x00000002	/* file may not be changed */
#define	UF_APPEND	0x00000004	/* writes to file may only append */
#define UF_OPAQUE	0x00000008	/* directory is opaque wrt. union */
/*
 * Super-user changeable flags.
 */
#define	SF_SETTABLE	0xffff0000	/* mask of superuser changeable flags */
#define	SF_ARCHIVED	0x00010000	/* file is archived */
#define	SF_IMMUTABLE	0x00020000	/* file may not be changed */
#define	SF_APPEND	0x00040000	/* writes to file may only append */

#ifdef KERNEL
/*
 * Shorthand abbreviations of above.
 */
#define	OPAQUE		(UF_OPAQUE)
#define	APPEND		(UF_APPEND | SF_APPEND)
#define	IMMUTABLE	(UF_IMMUTABLE | SF_IMMUTABLE)
#endif
#endif

#ifndef KERNEL

__BEGIN_DECLS
/* [XSI] */
int	chmod(const char *, mode_t);
int	fchmod(int, mode_t);
int	fstat(int, struct stat *);
int	lstat(const char *, struct stat *);
int	mkdir(const char *, mode_t);
int	mkfifo(const char *, mode_t);
int	stat(const char *, struct stat *);
int	mknod(const char *, mode_t, dev_t);
mode_t	umask(mode_t);

#ifndef _POSIX_C_SOURCE
#ifndef _FILESEC_T
struct _filesec;
typedef struct _filesec	*filesec_t;
#define _FILESEC_T
#endif
int	chflags(const char *, __uint32_t);
int	chmodx_np(const char *, filesec_t);
int	fchflags(int, __uint32_t);
int	fchmodx_np(int, filesec_t);
int	fstatx_np(int, struct stat *, filesec_t);
int	lstatx_np(const char *, struct stat *, filesec_t);
int	mkdirx_np(const char *, filesec_t);
int	mkfifox_np(const char *, filesec_t);
int	statx_np(const char *, struct stat *, filesec_t);
int	umaskx_np(filesec_t);
#endif	/* POSIX_C_SOURCE */
__END_DECLS
#endif
#endif /* !_SYS_STAT_H_ */
