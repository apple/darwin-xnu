#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>

#include <darwintest.h>

// rdar://58566604
// Exercise races of signal delivery vs exec in multi-threaded processes

T_GLOBAL_META(T_META_NAMESPACE("xnu.exec"),
    T_META_CHECK_LEAKS(false),
    T_META_ALL_VALID_ARCHS(true));

enum { KILL_ONCE, KILL_MANY, KILL_LAST } kill_mode;
enum { EXEC_FIRST, EXEC_SECOND, EXEC_LAST } exec_mode;

static int fd[2];

static void
do_exec(void)
{
	char echo_arg[50] = "";

	snprintf(echo_arg, sizeof(echo_arg), "            Child[%d] says hello after exec", getpid());

	char * new_argv[] = {
		"/bin/echo",
		echo_arg,
		NULL
	};

	int ret = execv(new_argv[0], new_argv);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "execv()");
}

static void*
thread_main(void* arg)
{
	T_LOG("mode: %d, %d: Child[%d] created second thread\n",
	    kill_mode, exec_mode, getpid());

	if (exec_mode == EXEC_SECOND) {
		int ret = dprintf(fd[1], "Hi!");
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "dprintf()");
		do_exec();
	}

	while (1) {
	}
	return NULL;
}

void
run_test(void)
{
	T_LOG("mode: %d, %d: Parent[%d]: forking\n",
	    kill_mode, exec_mode, getpid());

	pid_t child_pid = fork();

	T_QUIET; T_ASSERT_POSIX_SUCCESS(child_pid, "fork()");

	int ret = 0;

	if (child_pid == 0) {
		pthread_t thread;
		ret = pthread_create(&thread, NULL, thread_main, NULL);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_create()");

		if (exec_mode == EXEC_FIRST) {
			ret = dprintf(fd[1], "Hi!");
			T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "dprintf()");

			do_exec();
		}

		while (1) {
		}
	} else {
		char buffer[4] = "";
		ret = read(fd[0], buffer, sizeof(buffer));
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "read()");

		T_LOG("mode: %d, %d: Parent[%d]: got: '%s' from execing child, trying to kill and wait\n",
		    kill_mode, exec_mode, getpid(), buffer);

		int killcount = 0, status = 0, waitedpid = 0;

		switch (kill_mode) {
		case KILL_ONCE:
			ret = kill(child_pid, SIGKILL);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kill()");

			waitedpid = waitpid(child_pid, &status, 0);

			T_QUIET; T_ASSERT_POSIX_SUCCESS(waitedpid, "waitpid()");

			killcount++;
			break;
		case KILL_MANY:
			while (waitedpid == 0) {
				ret = kill(child_pid, SIGKILL);
				T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kill()");

				waitedpid = waitpid(child_pid, &status, WNOHANG);
				T_QUIET; T_ASSERT_POSIX_SUCCESS(waitedpid, "waitpid()");

				killcount++;
			}
			break;
		default:
			break;
		}

		T_LOG("mode: %d, %d: Parent[%d]: waitpid returned: %d, errno %d (%s), exit signal %d, after %d loops\n",
		    kill_mode, exec_mode, getpid(), waitedpid, errno, strerror(errno), WTERMSIG(status), killcount);
	}
}

T_DECL(exec_exit_race_once_first, "Exec-exit race, one kill, exec on first thread") {
	int rv = pipe(fd);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pipe()");

	kill_mode = KILL_ONCE;
	exec_mode = EXEC_FIRST;

	for (int i = 0; i < 1000; i++) {
		run_test();
	}
}

T_DECL(exec_exit_race_many_first, "Exec-exit race, many kill, exec on first thread") {
	int rv = pipe(fd);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pipe()");

	kill_mode = KILL_MANY;
	exec_mode = EXEC_FIRST;

	for (int i = 0; i < 1000; i++) {
		run_test();
	}
}

T_DECL(exec_exit_race_once_second, "Exec-exit race, one kill, exec on second thread") {
	int rv = pipe(fd);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pipe()");

	kill_mode = KILL_ONCE;
	exec_mode = EXEC_SECOND;

	for (int i = 0; i < 1000; i++) {
		run_test();
	}
}

T_DECL(exec_exit_race_many_second, "Exec-exit race, many kill, exec on second thread") {
	int rv = pipe(fd);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rv, "pipe()");

	kill_mode = KILL_MANY;
	exec_mode = EXEC_SECOND;

	for (int i = 0; i < 1000; i++) {
		run_test();
	}
}
