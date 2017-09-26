/*	$NetBSD: t_utimensat.c,v 1.6 2017/01/10 15:13:56 christos Exp $ */

/*-
 * Copyright (c) 2012 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Emmanuel Dreyfus.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/cdefs.h>
__RCSID("$NetBSD: t_utimensat.c,v 1.6 2017/01/10 15:13:56 christos Exp $");

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#define DIR "dir"
#define FILE "dir/utimensat"
#define BASEFILE "utimensat"
#define LINK "dir/symlink"
#define BASELINK "symlink"
#define FILEERR "dir/symlink"

static const struct timespec tptr[] = { 
	{ 0x12345678, 987654321 },
	{ 0x15263748, 123456789 },
};

static void chtmpdir(void)
{
	T_SETUPBEGIN;
	T_ASSERT_POSIX_ZERO(chdir(dt_tmpdir()), NULL);

	// <rdar://problem/31780295> dt_tmpdir() should guarantee a clean directory for each run
	unlink(FILE);
	unlink(LINK);
	rmdir(DIR);

	T_SETUPEND;
}

T_DECL(netbsd_utimensat_fd, "See that utimensat works with fd")
{
	chtmpdir();

	int dfd;
	int fd;
	struct stat st;

	T_ASSERT_POSIX_ZERO(mkdir(DIR, 0755), NULL);
	T_ASSERT_POSIX_SUCCESS((fd = open(FILE, O_CREAT|O_RDWR, 0644)), NULL);
	T_ASSERT_POSIX_ZERO(close(fd), NULL);

	T_ASSERT_POSIX_SUCCESS((dfd = open(DIR, O_RDONLY, 0)), NULL);
	T_ASSERT_POSIX_ZERO(utimensat(dfd, BASEFILE, tptr, 0), NULL);
	T_ASSERT_POSIX_ZERO(close(dfd), NULL);

	T_ASSERT_POSIX_ZERO(stat(FILE, &st), NULL);
	T_ASSERT_EQ(st.st_atimespec.tv_sec, tptr[0].tv_sec, NULL);
	T_ASSERT_EQ(st.st_atimespec.tv_nsec, tptr[0].tv_nsec, NULL);
	T_ASSERT_EQ(st.st_mtimespec.tv_sec, tptr[1].tv_sec, NULL);
	T_ASSERT_EQ(st.st_mtimespec.tv_nsec, tptr[1].tv_nsec, NULL);
}

T_DECL(netbsd_utimensat_fdcwd, "See that utimensat works with fd as AT_FDCWD")
{
	chtmpdir();

	int fd;
	struct stat st;

	T_ASSERT_POSIX_ZERO(mkdir(DIR, 0755), NULL);
	T_ASSERT_POSIX_SUCCESS((fd = open(FILE, O_CREAT|O_RDWR, 0644)), NULL);
	T_ASSERT_POSIX_ZERO(close(fd), NULL);

	T_ASSERT_POSIX_ZERO(chdir(DIR), NULL);
	T_ASSERT_POSIX_ZERO(utimensat(AT_FDCWD, BASEFILE, tptr, 0), NULL);

	T_ASSERT_POSIX_ZERO(stat(BASEFILE, &st), NULL);
	T_ASSERT_EQ(st.st_atimespec.tv_sec, tptr[0].tv_sec, NULL);
	T_ASSERT_EQ(st.st_atimespec.tv_nsec, tptr[0].tv_nsec, NULL);
	T_ASSERT_EQ(st.st_mtimespec.tv_sec, tptr[1].tv_sec, NULL);
	T_ASSERT_EQ(st.st_mtimespec.tv_nsec, tptr[1].tv_nsec, NULL);
}

T_DECL(netbsd_utimensat_fdcwderr, "See that utimensat fails with fd as AT_FDCWD and bad path")
{
	chtmpdir();

	T_ASSERT_POSIX_ZERO(mkdir(DIR, 0755), NULL);
	T_ASSERT_EQ(utimensat(AT_FDCWD, FILEERR, tptr, 0), -1, NULL);
}

T_DECL(netbsd_utimensat_fderr1, "See that utimensat fail with bad path")
{
	chtmpdir();

	int dfd;

	T_ASSERT_POSIX_ZERO(mkdir(DIR, 0755), NULL);
	T_ASSERT_POSIX_SUCCESS((dfd = open(DIR, O_RDONLY, 0)), NULL);
	T_ASSERT_EQ(utimensat(dfd, FILEERR, tptr, 0), -1, NULL);
	T_ASSERT_POSIX_ZERO(close(dfd), NULL);
}

T_DECL(netbsd_utimensat_fderr2, "See that utimensat fails with bad fdat")
{
	chtmpdir();

	int dfd;
	int fd;
	char cwd[MAXPATHLEN];

	T_ASSERT_POSIX_ZERO(mkdir(DIR, 0755), NULL);
	T_ASSERT_POSIX_SUCCESS((fd = open(FILE, O_CREAT|O_RDWR, 0644)), NULL);
	T_ASSERT_POSIX_ZERO(close(fd), NULL);

	T_ASSERT_POSIX_SUCCESS((dfd = open(getcwd(cwd, MAXPATHLEN), O_RDONLY, 0)), NULL);
	T_ASSERT_EQ(utimensat(dfd, BASEFILE, tptr, 0), -1, NULL);
	T_ASSERT_POSIX_ZERO(close(dfd), NULL);
}

T_DECL(netbsd_utimensat_fderr3, "See that utimensat fails with fd as -1")
{
	chtmpdir();

	int fd;

	T_ASSERT_POSIX_ZERO(mkdir(DIR, 0755), NULL);
	T_ASSERT_POSIX_SUCCESS((fd = open(FILE, O_CREAT|O_RDWR, 0644)), NULL);
	T_ASSERT_POSIX_ZERO(close(fd), NULL);

	T_ASSERT_EQ(utimensat(-1, FILE, tptr, 0), -1, NULL);
}

T_DECL(netbsd_utimensat_fdlink, "See that utimensat works on symlink")
{
	chtmpdir();

	int dfd;
	struct stat st;

	T_ASSERT_POSIX_ZERO(mkdir(DIR, 0755), NULL);
	T_ASSERT_POSIX_ZERO(symlink(FILE, LINK), NULL); /* NB: FILE does not exists */

	T_ASSERT_POSIX_SUCCESS((dfd = open(DIR, O_RDONLY, 0)), NULL);

	T_ASSERT_EQ(utimensat(dfd, BASELINK, tptr, 0), -1, NULL);
	T_ASSERT_EQ(errno, ENOENT, NULL);

	T_ASSERT_POSIX_ZERO(utimensat(dfd, BASELINK, tptr, AT_SYMLINK_NOFOLLOW), NULL);

	T_ASSERT_POSIX_ZERO(close(dfd), NULL);

	T_ASSERT_POSIX_ZERO(lstat(LINK, &st), NULL);
	T_ASSERT_EQ(st.st_atimespec.tv_sec, tptr[0].tv_sec, NULL);
	T_ASSERT_EQ(st.st_atimespec.tv_nsec, tptr[0].tv_nsec, NULL);
	T_ASSERT_EQ(st.st_mtimespec.tv_sec, tptr[1].tv_sec, NULL);
	T_ASSERT_EQ(st.st_mtimespec.tv_nsec, tptr[1].tv_nsec, NULL);
}
