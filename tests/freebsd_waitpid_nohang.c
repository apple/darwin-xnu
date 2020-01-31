/*-
 * Copyright (c) 2016 Jilles Tjoelker
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <sys/wait.h>

#include <darwintest.h>
#include <signal.h>
#include <unistd.h>

T_DECL(waitpid_nohang, "FreeBSDarwin--waitpid_nohang")
{
	pid_t child, pid;
	int status, r;
	siginfo_t siginfo;

	child = fork();
	T_ASSERT_POSIX_SUCCESS(child, "child forked successfully");
	if (child == 0) {
		sleep(10);
		_exit(1);
	}

	status = 42;
	pid = waitpid(child, &status, WNOHANG);
	T_ASSERT_POSIX_ZERO(pid, "waitpid call is successful");
	T_EXPECT_EQ(status, 42, "status is unaffected as expected");

	r = kill(child, SIGTERM);
	T_ASSERT_POSIX_ZERO(r, "signal sent successfully");
	r = waitid(P_PID, (id_t)child, &siginfo, WEXITED | WNOWAIT);
	T_ASSERT_POSIX_SUCCESS(r, "waitid call successful");

	status = -1;
	pid = waitpid(child, &status, WNOHANG);
	T_ASSERT_EQ(pid, child, "waitpid returns correct pid");
	T_EXPECT_EQ(WIFSIGNALED(status), true, "child was signaled");
	T_EXPECT_EQ(WTERMSIG(status), SIGTERM, "child was sent SIGTERM");
}
