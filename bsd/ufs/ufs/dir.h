/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/*
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
 *	@(#)dir.h	8.5 (Berkeley) 4/27/95
 */

#ifndef _DIR_H_
#define	_DIR_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_UNSTABLE
/*
 * Theoretically, directories can be more than 2Gb in length, however, in
 * practice this seems unlikely. So, we define the type doff_t as a 32-bit
 * quantity to keep down the cost of doing lookup on a 32-bit machine.
 */
#define	doff_t		int32_t
#define MAXDIRSIZE	(0x7fffffff)

/*
 * A directory consists of some number of blocks of DIRBLKSIZ
 * bytes, where DIRBLKSIZ is chosen such that it can be transferred
 * to disk in a single atomic operation (e.g. 512 bytes on most machines).
 *
 * Each DIRBLKSIZ byte block contains some number of directory entry
 * structures, which are of variable length.  Each directory entry has
 * a struct direct at the front of it, containing its inode number,
 * the length of the entry, and the length of the name contained in
 * the entry.  These are followed by the name padded to a 4 byte boundary
 * with null bytes.  All names are guaranteed null terminated.
 * The maximum length of a name in a directory is MAXNAMLEN.
 *
 * The macro DIRSIZ(fmt, dp) gives the amount of space required to represent
 * a directory entry.  Free space in a directory is represented by
 * entries which have dp->d_reclen > DIRSIZ(fmt, dp).  All DIRBLKSIZ bytes
 * in a directory block are claimed by the directory entries.  This
 * usually results in the last entry in a directory having a large
 * dp->d_reclen.  When entries are deleted from a directory, the
 * space is returned to the previous entry in the same directory
 * block by increasing its dp->d_reclen.  If the first entry of
 * a directory block is free, then its dp->d_ino is set to 0.
 * Entries other than the first in a directory do not normally have
 * dp->d_ino set to 0.
 */
#ifdef __APPLE__
#define DIRBLKSIZ	1024
#else
#define DIRBLKSIZ	DEV_BSIZE
#endif
#define	MAXNAMLEN	255

struct	direct {
	u_int32_t d_ino;		/* inode number of entry */
	u_int16_t d_reclen;		/* length of this record */
	u_int8_t  d_type; 		/* file type, see below */
	u_int8_t  d_namlen;		/* length of string in d_name */
	char	  d_name[MAXNAMLEN + 1];/* name with length <= MAXNAMLEN */
};

/*
 * File types
 */
#define	DT_UNKNOWN	 0
#define	DT_FIFO		 1
#define	DT_CHR		 2
#define	DT_DIR		 4
#define	DT_BLK		 6
#define	DT_REG		 8
#define	DT_LNK		10
#define	DT_SOCK		12
#define	DT_WHT		14

/*
 * Convert between stat structure types and directory types.
 */
#define	IFTODT(mode)	(((mode) & 0170000) >> 12)
#define	DTTOIF(dirtype)	((dirtype) << 12)

/*
 * The DIRSIZ macro gives the minimum record length which will hold
 * the directory entry.  This requires the amount of space in struct direct
 * without the d_name field, plus enough space for the name with a terminating
 * null byte (dp->d_namlen+1), rounded up to a 4 byte boundary.
 */
#if (BYTE_ORDER == LITTLE_ENDIAN)
#define DIRSIZ(oldfmt, dp) \
    ((oldfmt) ? \
    ((sizeof(struct direct) - (MAXNAMLEN+1)) + (((dp)->d_type+1 + 3) &~ 3)) : \
    ((sizeof(struct direct) - (MAXNAMLEN+1)) + (((dp)->d_namlen+1 + 3) &~ 3)))
#else
#define DIRSIZ(oldfmt, dp) \
    ((sizeof(struct direct) - (MAXNAMLEN+1)) + (((dp)->d_namlen+1 + 3) &~ 3))
#endif
#define OLDDIRFMT	1
#define NEWDIRFMT	0

/*
 * Template for manipulating directories.  Should use struct direct's,
 * but the name field is MAXNAMLEN - 1, and this just won't do.
 */
struct dirtemplate {
	u_int32_t	dot_ino;
	int16_t		dot_reclen;
	u_int8_t	dot_type;
	u_int8_t	dot_namlen;
	char		dot_name[4];	/* must be multiple of 4 */
	u_int32_t	dotdot_ino;
	int16_t		dotdot_reclen;
	u_int8_t	dotdot_type;
	u_int8_t	dotdot_namlen;
	char		dotdot_name[4];	/* ditto */
};

/*
 * This is the old format of directories, sanz type element.
 */
struct odirtemplate {
	u_int32_t	dot_ino;
	int16_t		dot_reclen;
	u_int16_t	dot_namlen;
	char		dot_name[4];	/* must be multiple of 4 */
	u_int32_t	dotdot_ino;
	int16_t		dotdot_reclen;
	u_int16_t	dotdot_namlen;
	char		dotdot_name[4];	/* ditto */
};
#endif /* __APPLE_API_UNSTABLE */
#endif /* !_DIR_H_ */
