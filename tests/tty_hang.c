/*
 * Copyright (c) 2015-2018 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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


#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <util.h>
#include <syslog.h>
#include <termios.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include <darwintest_multiprocess.h>

#define TEST_TIMEOUT	10

/*
 * Receiving SIGTTIN (from the blocked read) is the passing condition, we just
 * catch it so that we don't get terminated when we receive this.
 */
void
handle_sigttin(int signal)
{
	return;
}

/*
 * Because of the way dt_fork_helpers work, we have to ensure any children
 * created by this function calls exit instead of getting the fork handlers exit
 * handling
 */
int
get_new_session_and_terminal_and_fork_child_to_read(char *pty_name)
{
	int sock_fd[2];
	int pty_fd;
	pid_t pid;
	char buf[10];

	/*
	 * We use this to handshake certain actions between this process and its
	 * child.
	 */
	T_ASSERT_POSIX_SUCCESS(socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fd),
	   NULL);
	
	/*
	 * New session, lose any existing controlling terminal and become
	 * session leader.
	 */
	T_ASSERT_POSIX_SUCCESS(setsid(), NULL);
	
	/* now open pty, become controlling terminal of new session */
	T_ASSERT_POSIX_SUCCESS(pty_fd = open(pty_name, O_RDWR), NULL);
	
	T_ASSERT_POSIX_SUCCESS(pid = fork(), NULL);

	if (pid == 0) { /* child */
		int pty_fd_child;
		char buf[10];
		
		T_ASSERT_POSIX_SUCCESS(close(sock_fd[0]), NULL);
		T_ASSERT_POSIX_SUCCESS(close(pty_fd), NULL);

		/* Make a new process group for ourselves */
		T_ASSERT_POSIX_SUCCESS(setpgid(0, 0), NULL);

		T_ASSERT_POSIX_SUCCESS(pty_fd_child = open(pty_name, O_RDWR),
		    NULL);

		/* now let parent know we've done open and setpgid */
		write(sock_fd[1], "done", sizeof("done"));

		/* wait for parent to set us to the foreground process group */
		read(sock_fd[1], buf, sizeof(buf));

		/*
		 * We are the foreground process group now so we can read
		 * without getting a SIGTTIN.
		 *
		 * Once we are blocked though (we have a crude 1 second sleep on
		 * the parent to "detect" this), our parent is going to change
		 * us to be in the background.
		 *
		 * We'll be blocked until we get a signal and if that is signal
		 * is SIGTTIN, then the test has passed otherwise the test has
		 * failed.
		 */
		signal(SIGTTIN, handle_sigttin);
		(void)read(pty_fd_child, buf, sizeof(buf));
		/*
		 * If we get here, we passed, if we get any other signal than
		 * SIGTTIN, we will not reach here.
		 */
		exit(0);
	}
	
	T_ASSERT_POSIX_SUCCESS(close(sock_fd[1]), NULL);
	
	/* wait for child to open slave side and set its pgid to its pid */
	T_ASSERT_POSIX_SUCCESS(read(sock_fd[0], buf, sizeof(buf)), NULL);
	
	/*
	 * We need this to happen and in the order shown
	 *
	 * parent (pgid = pid)                  child (child_pgid = child_pid)
	 *
	 * 1 - tcsetpgrp(child_pgid)
	 * 2 -                                      block in read()
	 * 3 - tcsetpgrp(pgid)
	 *
	 * making sure 2 happens after 1 is easy, we use a sleep(1) in the
	 * parent to try and ensure 3 happens after 2.
	 */

	T_ASSERT_POSIX_SUCCESS(tcsetpgrp(pty_fd, pid), NULL);
	
	/* let child know you have set it to be the foreground process group */
	T_ASSERT_POSIX_SUCCESS(write(sock_fd[0], "done", sizeof("done")), NULL);
	
	/*
	 * give it a second to do the read of the terminal in response.
	 *
	 * XXX : Find a way to detect that the child is blocked in read(2).
	 */
	sleep(1);
	
	/*
	 * now change the foreground process group to ourselves -
	 * Note we are now in the background process group and we need to ignore
	 * SIGTTOU for this call to succeed.
	 *
	 * Hopefully the child has gotten to run and blocked for read on the
	 * terminal in the 1 second we slept.
	 */
	signal(SIGTTOU, SIG_IGN);
	T_ASSERT_POSIX_SUCCESS(tcsetpgrp(pty_fd, getpid()), NULL);

	return (0);
}

/*
 * We're running in a "fork helper", we can't do a waitpid on the child because
 * the fork helper unhelpfully hides the pid of the child and in it kills itself.
 * We will instead fork first and wait on the child. If it is
 * able to emerge from the read of the terminal, the test passes and if it
 * doesn't, the test fails.
 * Since the test is testing for a deadlock in proc_exit of the child (caused
 * by a background read in the "grandchild".
 */
void
run_test(int do_revoke)
{
	int master_fd;
	char *slave_pty;
	pid_t pid;

	T_WITH_ERRNO;
	T_QUIET;

	T_SETUPBEGIN;
	
	slave_pty= NULL;
	T_ASSERT_POSIX_SUCCESS(master_fd = posix_openpt(O_RDWR | O_NOCTTY),
	    NULL);
	(void)fcntl(master_fd, F_SETFL, O_NONBLOCK);
	T_ASSERT_POSIX_SUCCESS(grantpt(master_fd), NULL);
	T_ASSERT_POSIX_SUCCESS(unlockpt(master_fd), NULL);
	slave_pty= ptsname(master_fd);
	T_ASSERT_NOTNULL(slave_pty, NULL);
	T_LOG("slave pty is %s\n", slave_pty);

	T_SETUPEND;
	
	/*
	 * We get the stdin and stdout redirection but we don't have visibility
	 * into the child (nor can we wait for it). To get around that, we fork
	 * and only let the parent to the caller and the child exits before
	 * returning to the caller.
	 */
	T_ASSERT_POSIX_SUCCESS(pid = fork(), NULL);
	
	if (pid == 0) { /* child */
		T_ASSERT_POSIX_SUCCESS(close(master_fd), NULL);
		get_new_session_and_terminal_and_fork_child_to_read(slave_pty);

		/*
		 * These tests are for testing revoke and read hangs. This
		 * revoke can be explicit by a revoke(2) system call (test 2)
		 * or as part of exit(2) of the session leader (test 1).
		 * The exit hang is the common hang and can be fixed
		 * independently but fixing the revoke(2) hang requires us make
		 * changes in the tcsetpgrp path ( which also fixes the exit
		 * hang). In essence, we have 2 fixes. One which only addresses
		 * the exit hang and one which fixes both.
		 */
		if (do_revoke) {
			/* This should not hang for the test to pass .. */
			T_ASSERT_POSIX_SUCCESS(revoke(slave_pty), NULL);
		}
		/*
		 * This child has the same dt_helper variables as its parent
		 * The way dt_fork_helpers work if we don't exit() from here,
		 * we will be killing the parent. So we have to exit() and not
		 * let the dt_fork_helpers continue.
		 * If we didn't do the revoke(2), This test passes if this exit
		 * doesn't hang waiting for its child to finish reading.
		 */
		exit(0);
	}

	int status;
	int sig;

	dt_waitpid(pid, &status, &sig, 0);
	if (sig) {
		T_FAIL("Test failed because child received signal %s\n",
		       strsignal(sig));
	} else if (status) {
		T_FAIL("Test failed because child exited with status %d\n",
		       status);
	} else {
		T_PASS("test_passed\n");
	}
	/*
	 * we can let this process proceed with the regular darwintest process
	 * termination and cleanup.
	 */
}


/*************************** TEST 1 ********************************/
T_HELPER_DECL(create_new_session_and_exit, "create_new_session_and_exit") {
	run_test(0);
}

T_DECL(tty_exit_bgread_hang_test, "test for background read hang on ttys with proc exit")
{
	dt_helper_t helpers[1];
	
	helpers[0] = dt_fork_helper("create_new_session_and_exit");
	dt_run_helpers(helpers, 1, TEST_TIMEOUT);
}
/***********************  END TEST 1  ********************************/

/************************** TEST 2 ***********************************/
T_HELPER_DECL(create_new_session_and_revoke_terminal, "create_new_session_and_revoke_terminal") {
	run_test(1);
}

T_DECL(tty_revoke_bgread_hang_test, "test for background read hang on ttys with revoke")
{
	dt_helper_t helpers[1];
	
	helpers[0] = dt_fork_helper("create_new_session_and_revoke_terminal");
	dt_run_helpers(helpers, 1, TEST_TIMEOUT);
}
/***********************  END TEST 2 *********************************/

