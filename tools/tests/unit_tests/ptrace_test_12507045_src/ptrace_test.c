#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <err.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/event.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <sys/proc.h>
#include <libproc.h>
#include <stdarg.h>

/*
 * We create a process hierarchy of:
 *
 * grandparent -> parent -> child
 *                   \
 *                    \--> debugger
 *
 * When the debugger calls ptrace(2) on child, it
 * is temporarily reparented.
 *
 * We may also create a hierarchy of:
 *
 * grandparent -> parent/debugger -> child
 *
 */

typedef enum {
	eParentExitAfterWaitpid = 0,
	eParentExitAfterWaitpidAndSIGCHLD,
	eParentExitBeforeWaitpid,
	eParentExitAfterDebuggerAttach,
	eParentExitBeforeDebuggerAttach,
	eParentIsDebugger
} parent_exit_t;

typedef enum {
	eDebuggerExitAfterKillAndWaitpid = 0,
	eDebuggerExitAfterKillWithoutWaitpid,
	eDebuggerExitAfterDetach,
	eDebuggerExitWithoutDetach
} debugger_exit_t;

void do_grandparent(pid_t parent, pid_t child, pid_t debugger, debugger_exit_t debugger_exit_time) __attribute__((noreturn));
void do_parent(pid_t child, pid_t debugger, parent_exit_t parent_exit_time, debugger_exit_t debugger_exit_time) __attribute__((noreturn));
void do_child(void) __attribute__((noreturn));
void do_debugger(pid_t child, debugger_exit_t debugger_exit_time) __attribute__((noreturn));

bool iszombie(pid_t p);

char *str_kev_filter(int filter);
char *str_kev_flags(int filter, uint16_t flags);
char *str_kev_fflags(int filter, uint32_t fflags);
char *str_kev_data(int filter, uint32_t fflags, int64_t data, uint64_t udata);
char *print_exit(pid_t p, int stat_loc);

void logline(const char *format, ...);

void usage(void);
int test_all_permutations(void);
void test(parent_exit_t parent_exit_time, debugger_exit_t debugger_exit_time) __attribute__((noreturn));

int main(int argc, char *argv[]) {
	int ch;

	int parent_exit_time = -1;
	int debugger_exit_time = -1;

	while ((ch = getopt(argc, argv, "p:w:")) != -1) {
		switch (ch) {
			case 'p':
				parent_exit_time = atoi(optarg);
				break;
			case 'w':
				debugger_exit_time = atoi(optarg);
				break;
			case '?':
			default:
				usage();
		}
	}

	/* no explicit options, loop through them all */
	if (parent_exit_time == -1 &&
		debugger_exit_time == -1) {
		return test_all_permutations();
	}

	if (parent_exit_time == -1 ||
		debugger_exit_time == -1) {
		usage();
	}

	test((parent_exit_t)parent_exit_time,
		 (debugger_exit_t)debugger_exit_time);

	return 0; /* never reached */
}

void test(parent_exit_t parent_exit_time, debugger_exit_t debugger_exit_time)
{	
	pid_t parent, child, debugger;
	int ret;
	int fds[2];

	/* pipe for parent to send child pid to grandparent */
	ret = pipe(fds);
	if (-1 == ret) {
		err(1, "failed to create pipe");
	}

	parent = fork();
	if (parent == 0) {
		/* parent sub-branch */

		ret = close(fds[0]);
		if (ret == -1) {
			err(1, "close read end of pipe");
		}

		child = fork();
		if (child == 0) {
			/* child */
			ret = close(fds[1]);
			if (ret == -1) {
				err(1, "close write end of pipe");
			}

			do_child();
		} else if (child == -1) {
			err(1, "parent failed to fork child");
		} else {
			/* parent */
			if (-1 == write(fds[1], &child, sizeof(child))) {
				err(1, "writing child pid to grandparent");
			}

			if (parent_exit_time == eParentIsDebugger) {
				debugger = -1;

				if (-1 == write(fds[1], &debugger, sizeof(debugger))) {
					err(1, "writing debugger pid to grandparent");
				}
				ret = close(fds[1]);
				if (ret == -1) {
					err(1, "close write end of pipe");
				}

				do_debugger(child, debugger_exit_time);
			} else {
				debugger = fork();
				if (debugger == 0) {
					/* debugger */
					ret = close(fds[1]);
					if (ret == -1) {
						err(1, "close write end of pipe");
					}

					do_debugger(child, debugger_exit_time);
				} else if (debugger == -1) {
					err(1, "parent failed to fork debugger");
				} else {
					/* still parent */
					if (-1 == write(fds[1], &debugger, sizeof(debugger))) {
						err(1, "writing debugger pid to grandparent");
					}
					ret = close(fds[1]);
					if (ret == -1) {
						err(1, "close write end of pipe");
					}
					
					do_parent(child, debugger, parent_exit_time, debugger_exit_time);
				}
			}
		}
	} else if (parent == -1) {
		err(1, "grandparent failed to fork parent");
	} else {
		ret = close(fds[1]);
		if (ret == -1) {
			err(1, "close write end of pipe");
		}

		if (-1 == read(fds[0], &child, sizeof(child))) {
			err(1, "could not read child pid");
		}

		if (-1 == read(fds[0], &debugger, sizeof(debugger))) {
			err(1, "could not read debugger pid");
		}

		ret = close(fds[0]);
		if (ret == -1) {
			err(1, "close read end of pipe");
		}

		do_grandparent(parent, child, debugger, debugger_exit_time);
	}
}

void usage(void)
{
	errx(1, "Usage: %s [-p <parent_exit_time> -w <debugger_exit_time>]", getprogname());
}

int test_all_permutations(void)
{
	int p, w;
	bool has_failure = false;

	for (p = 0; p <= 5; p++) {
		for (w = 0; w <= 3; w++) {
			int testpid;
			int ret;
			
			testpid = fork();
			if (testpid == 0) {
				logline("-------------------------------------------------------");
				logline("*** Executing self-test: %s -p %d -w %d",
						getprogname(), p, w);
				test((parent_exit_t)p,
					 (debugger_exit_t)w);
				_exit(1); /* never reached */
			} else if (testpid == -1) {
				err(1, "failed to fork test pid");
			} else {
				int stat_loc;
				
				ret = waitpid(testpid, &stat_loc, 0);
				if (ret == -1)
					err(1, "waitpid(%d) by test harness failed", testpid);
				
				logline("test process: %s", print_exit(testpid, stat_loc));
				if (!WIFEXITED(stat_loc) || (0 != WEXITSTATUS(stat_loc))) {
					logline("FAILED TEST");
					has_failure = true;
				}
			}
		}
	}

	if (has_failure) {
		logline("test failures found");
		return 1;
	}

	return 0;
}

void do_grandparent(pid_t parent, pid_t child, pid_t debugger, debugger_exit_t debugger_exit_time)
{
	pid_t result;
	int stat_loc;
	int exit_code = 0;
	int kq;
	int ret;
	struct kevent64_s kev;
	int neededdeathcount = (debugger != -1) ? 3 : 2;

	setprogname("GRANDPARENT");

	logline("grandparent pid %d has parent pid %d and child pid %d. waiting for parent process exit...", getpid(), parent, child);

	/* make sure we can at least observe real child's exit */
	kq = kqueue();
	if (kq < 0)
		err(1, "kqueue");

	EV_SET64(&kev, child, EVFILT_PROC, EV_ADD|EV_ENABLE,
			 NOTE_EXIT, 0, child, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret == -1)
		err(1, "kevent64 EVFILT_PROC");

	EV_SET64(&kev, parent, EVFILT_PROC, EV_ADD|EV_ENABLE,
			 NOTE_EXIT, 0, parent, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret == -1)
		err(1, "kevent64 EVFILT_PROC");

	if (debugger != -1) {
		EV_SET64(&kev, debugger, EVFILT_PROC, EV_ADD|EV_ENABLE,
				 NOTE_EXIT, 0, debugger, 0, 0);
		ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
		if (ret == -1)
			err(1, "kevent64 EVFILT_PROC");
	}

	EV_SET64(&kev, 5, EVFILT_TIMER, EV_ADD|EV_ENABLE|EV_ONESHOT,
			 NOTE_SECONDS, 5, 0, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret == -1)
		err(1, "kevent64 EVFILT_TIMER");

	while(1) {

		ret = kevent64(kq, NULL, 0, &kev, 1, 0, NULL);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			err(1, "kevent64");
		} else if (ret == 0) {
			break;
		}

		logline("kevent64 returned ident %llu filter %s fflags %s data %s",
				kev.ident, str_kev_filter(kev.filter),
				str_kev_fflags(kev.filter, kev.fflags),
				str_kev_data(kev.filter, kev.fflags, kev.data, kev.udata));
		if (kev.filter == EVFILT_PROC) {
			if (child == kev.udata) {
				neededdeathcount--;
			} else if (parent == kev.udata) {
				neededdeathcount--;
			} else if ((debugger != -1) && (debugger == kev.udata)) {
				neededdeathcount--;
			}
		} else if (kev.filter == EVFILT_TIMER) {
			logline("timed out waiting for NOTE_EXIT");
			exit_code = 1;
			break;
		}

		if (neededdeathcount == 0) {
			break;
		}
	}

	result = waitpid(parent, &stat_loc, 0);
	if (result == -1)
		err(1, "waitpid(%d) by grandparent failed", parent);

  
	logline("parent process: %s", print_exit(parent, stat_loc));
	if (!WIFEXITED(stat_loc) || (0 != WEXITSTATUS(stat_loc))) {
		exit_code = 1;
	}

	if (iszombie(parent)) {
		logline("parent %d is now a zombie", parent);
		exit_code = 1;
	}

	if (iszombie(child)) {
		logline("child %d is now a zombie", child);
		exit_code = 1;
	}

	if ((debugger != -1) && iszombie(debugger)) {
		logline("debugger %d is now a zombie", debugger);
		exit_code = 1;
	}

	exit(exit_code);
}

/*
 * debugger will register kevents, wait for quorum on events, then exit
 */
void do_parent(pid_t child, pid_t debugger, parent_exit_t parent_exit_time, debugger_exit_t debugger_exit_time)
{
	int kq;
	int ret;
	struct kevent64_s kev;
	int deathcount = 0;
	int childsignalcount = 0;
	int stat_loc;

	setprogname("PARENT");

	logline("parent pid %d has child pid %d and debugger pid %d. waiting for processes to exit...", getpid(), child, debugger);

	kq = kqueue();
	if (kq < 0)
		err(1, "kqueue");

	EV_SET64(&kev, child, EVFILT_PROC, EV_ADD|EV_ENABLE,
			 NOTE_EXIT|NOTE_EXITSTATUS|NOTE_EXIT_DETAIL|NOTE_FORK|NOTE_EXEC|NOTE_SIGNAL,
			 0, child, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret == -1)
		err(1, "kevent64 EVFILT_PROC");
  
	EV_SET64(&kev, SIGCHLD, EVFILT_SIGNAL, EV_ADD|EV_ENABLE,
			 0, 0, child, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret == -1)
		err(1, "kevent64 EVFILT_SIGNAL");

	EV_SET64(&kev, 7, EVFILT_TIMER, EV_ADD|EV_ENABLE|EV_ONESHOT,
			 NOTE_SECONDS, 7, 0, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret == -1)
		err(1, "kevent64 EVFILT_TIMER");

	while(1) {
		ret = kevent64(kq, NULL, 0, &kev, 1, 0, NULL);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			err(1, "kevent64");
		} else if (ret == 0) {
			break;
		}

		logline("kevent64 returned ident %llu filter %s fflags %s data %s",
				kev.ident, str_kev_filter(kev.filter),
				str_kev_fflags(kev.filter, kev.fflags),
				str_kev_data(kev.filter, kev.fflags, kev.data, kev.udata));
		if (kev.filter == EVFILT_SIGNAL) {
			/* must be SIGCHLD */
			deathcount++;
		} else if (kev.filter == EVFILT_PROC) {
			if (child == kev.udata) {
				if ((kev.fflags & (NOTE_EXIT|NOTE_EXITSTATUS)) == (NOTE_EXIT|NOTE_EXITSTATUS)) {
					deathcount++;
				} else if (kev.fflags & NOTE_SIGNAL) {
					childsignalcount++;
					if ((parent_exit_time == eParentExitAfterDebuggerAttach) && (childsignalcount >= 2)) {
						/* second signal is attach */
						logline("exiting because of eParentExitAfterDebuggerAttach");
						exit(0);
					}
				} else if (kev.fflags & NOTE_FORK) {
					if (parent_exit_time == eParentExitBeforeDebuggerAttach) {
						logline("exiting because of eParentExitBeforeDebuggerAttach");
						exit(0);
					}
				}
			}
		} else if (kev.filter == EVFILT_TIMER) {
			errx(1, "timed out waiting for NOTE_EXIT");
		}

		if (deathcount >= (parent_exit_time == eParentExitAfterWaitpidAndSIGCHLD ? 2 : 1)) {
			break;
		}
	}

	if (parent_exit_time == eParentExitBeforeWaitpid) {
		logline("exiting because of eParentExitBeforeWaitpid");
		exit(0);
	}

	ret = waitpid(child, &stat_loc, 0);
	if (ret == -1)
		err(1, "waitpid(%d) by parent failed", child);

	logline("child process: %s", print_exit(child, stat_loc));
	if (!WIFSIGNALED(stat_loc) || (SIGKILL != WTERMSIG(stat_loc)))
		errx(1, "child did not exit as expected");

	ret = waitpid(debugger, &stat_loc, 0);
	if (ret == -1)
		err(1, "waitpid(%d) by parent failed", debugger);

	logline("debugger process: %s", print_exit(debugger, stat_loc));
	if (!WIFEXITED(stat_loc) || (0 != WEXITSTATUS(stat_loc)))
		errx(1, "debugger did not exit as expected");

	/* Received both SIGCHLD and NOTE_EXIT, as needed */
	logline("exiting beacuse of eParentExitAfterWaitpid/eParentExitAfterWaitpidAndSIGCHLD");
	exit(0);
}

/* child will spin waiting to be killed by debugger or parent or someone */
void do_child(void)
{
	pid_t doublechild;
	int ret;
	setprogname("CHILD");

	logline("child pid %d. waiting for external termination...", getpid());

	usleep(500000);

	doublechild = fork();
	if (doublechild == 0) {
		exit(0);
	} else if (doublechild == -1) {
		err(1, "doublechild");
	} else {
		ret = waitpid(doublechild, NULL, 0);
		if (ret == -1)
			err(1, "waitpid(%d) by parent failed", doublechild);
	}

	while (1) {
		sleep(60);
	}
}

/*
 * debugger will register kevents, attach+kill child, wait for quorum on events,
 * then exit.
 */
void do_debugger(pid_t child, debugger_exit_t debugger_exit_time)
{
	int kq;
	int ret;
	struct kevent64_s kev;
	int deathcount = 0;
	int stat_loc;

	setprogname("DEBUGGER");

	logline("debugger pid %d has child pid %d. waiting for process exit...", getpid(), child);
  
	sleep(1);
	fprintf(stderr, "\n");
	ret = ptrace(PT_ATTACH, child, 0, 0);
	if (ret == -1)
		err(1, "ptrace(PT_ATTACH)");

	ret = waitpid(child, &stat_loc, WUNTRACED);
	if (ret == -1)
		err(1, "waitpid(child, WUNTRACED)");

	logline("child process stopped: %s", print_exit(child, stat_loc));

	if (debugger_exit_time == eDebuggerExitWithoutDetach) {
		logline("exiting because of eDebuggerExitWithoutDetach");
		exit(0);
	} else if (debugger_exit_time == eDebuggerExitAfterDetach) {
		ret = ptrace(PT_DETACH, child, 0, 0);
		if (ret == -1)
			err(1, "ptrace(PT_DETACH)");

		ret = kill(child, SIGKILL);
		if (ret == -1)
			err(1, "kill(SIGKILL)");

		logline("exiting because of eDebuggerExitAfterDetach");
		exit(0);
	}

	kq = kqueue();
	if (kq < 0)
		err(1, "kqueue");

	EV_SET64(&kev, child, EVFILT_PROC, EV_ADD|EV_ENABLE,
			 NOTE_EXIT|NOTE_EXITSTATUS|NOTE_EXIT_DETAIL|NOTE_FORK|NOTE_EXEC|NOTE_SIGNAL,
			 0, child, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret == -1)
		err(1, "kevent64 EVFILT_PROC");
  
	EV_SET64(&kev, SIGCHLD, EVFILT_SIGNAL, EV_ADD|EV_ENABLE,
			 0, 0, child, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret == -1)
		err(1, "kevent64 EVFILT_SIGNAL");

	sleep(1);
	fprintf(stderr, "\n");
	ret = ptrace(PT_KILL, child, 0, 0);
	if (ret == -1)
		err(1, "ptrace(PT_KILL)");
  
	while(1) {
		ret = kevent64(kq, NULL, 0, &kev, 1, 0, NULL);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			err(1, "kevent64");
		} else if (ret == 0) {
			continue;
		}

		logline("kevent64 returned ident %llu filter %s fflags %s data %s",
				kev.ident, str_kev_filter(kev.filter),
				str_kev_fflags(kev.filter, kev.fflags),
				str_kev_data(kev.filter, kev.fflags, kev.data, kev.udata));
		if (kev.filter == EVFILT_SIGNAL) {
			/* must be SIGCHLD */
			deathcount++;
		} else if (kev.filter == EVFILT_PROC) {
			if ((kev.fflags & (NOTE_EXIT|NOTE_EXITSTATUS)) == (NOTE_EXIT|NOTE_EXITSTATUS)) {
				deathcount++;
			}
		}

		if (deathcount >= 2) {
			break;
		}
	}

	if (debugger_exit_time == eDebuggerExitAfterKillWithoutWaitpid) {
		logline("exiting because of eDebuggerExitAfterKillWithoutWaitpid");
		exit(0);
	}

	sleep(1);
	fprintf(stderr, "\n");
	ret = waitpid(child, &stat_loc, 0);
	if (ret == -1)
		err(1, "waitpid(%d) by debugger failed", child);
	
	logline("child process: %s", print_exit(child, stat_loc));

	/* Received both SIGCHLD and NOTE_EXIT */
	exit(0);
}

void logline(const char *format, ...)
{
	char *line = NULL;
	char newformat[1024];
		
	snprintf(newformat, sizeof(newformat),  "%s: %s\n", getprogname(), format);

	va_list va;

	va_start(va, format);
	vasprintf(&line, newformat, va);
	va_end(va);
	
	if (line) {
		write(STDOUT_FILENO, line, strlen(line));
		free(line);
	} else {
		write(STDOUT_FILENO, "error\n", 6);
	}
}


char *str_kev_filter(int filter)
{
	static char filter_string[32];
	if (filter == EVFILT_PROC)
		strlcpy(filter_string, "EVFILT_PROC", sizeof(filter_string));
	else if (filter == EVFILT_SIGNAL)
		strlcpy(filter_string, "EVFILT_SIGNAL", sizeof(filter_string));
	else if (filter == EVFILT_TIMER)
		strlcpy(filter_string, "EVFILT_TIMER", sizeof(filter_string));
	else
		strlcpy(filter_string, "EVFILT_UNKNOWN", sizeof(filter_string));

	return filter_string;
}

char *str_kev_flags(int filter, uint16_t flags)
{
	static char flags_string[128];

	flags_string[0] = '\0';
	if (filter & EV_ADD) strlcat(flags_string, "|EV_ADD", sizeof(flags_string));
	if (filter & EV_DELETE) strlcat(flags_string, "|EV_DELETE", sizeof(flags_string));
	if (filter & EV_ENABLE) strlcat(flags_string, "|EV_ENABLE", sizeof(flags_string));
	if (filter & EV_DISABLE) strlcat(flags_string, "|EV_DISABLE", sizeof(flags_string));
	if (filter & EV_RECEIPT) strlcat(flags_string, "|EV_RECEIPT", sizeof(flags_string));
	if (filter & EV_ONESHOT) strlcat(flags_string, "|EV_ONESHOT", sizeof(flags_string));
	if (filter & EV_CLEAR) strlcat(flags_string, "|EV_CLEAR", sizeof(flags_string));
	if (filter & EV_DISPATCH) strlcat(flags_string, "|EV_DISPATCH", sizeof(flags_string));
	if (filter & EV_EOF) strlcat(flags_string, "|EV_EOF", sizeof(flags_string));
	if (filter & EV_ERROR) strlcat(flags_string, "|EV_ERROR", sizeof(flags_string));

	if (flags_string[0] == '|')
		return &flags_string[1];
	else
		return flags_string;
}

char *str_kev_fflags(int filter, uint32_t fflags)
{
	static char fflags_string[128];

	fflags_string[0] = '\0';

	if (filter == EVFILT_SIGNAL) {
		if (fflags & NOTE_SIGNAL) strlcat(fflags_string, "|NOTE_SIGNAL", sizeof(fflags_string));
	} else if (filter == EVFILT_PROC) {
		if (fflags & NOTE_EXIT) strlcat(fflags_string, "|NOTE_EXIT", sizeof(fflags_string));
		if (fflags & NOTE_FORK) strlcat(fflags_string, "|NOTE_FORK", sizeof(fflags_string));
		if (fflags & NOTE_EXEC) strlcat(fflags_string, "|NOTE_EXEC", sizeof(fflags_string));
		if (fflags & NOTE_SIGNAL) strlcat(fflags_string, "|NOTE_SIGNAL", sizeof(fflags_string));
		if (fflags & NOTE_EXITSTATUS) strlcat(fflags_string, "|NOTE_EXITSTATUS", sizeof(fflags_string));
		if (fflags & NOTE_EXIT_DETAIL) strlcat(fflags_string, "|NOTE_EXIT_DETAIL", sizeof(fflags_string));
		if (fflags & NOTE_EXIT_DECRYPTFAIL) strlcat(fflags_string, "|NOTE_EXIT_DECRYPTFAIL", sizeof(fflags_string));
		if (fflags & NOTE_EXIT_MEMORY) strlcat(fflags_string, "|NOTE_EXIT_MEMORY", sizeof(fflags_string));
#ifdef NOTE_EXIT_CSERROR
		if (fflags & NOTE_EXIT_CSERROR) strlcat(fflags_string, "|NOTE_EXIT_CSERROR", sizeof(fflags_string));
#endif
	} else if (filter == EVFILT_TIMER) {
		if (fflags & NOTE_SECONDS) strlcat(fflags_string, "|NOTE_SECONDS", sizeof(fflags_string));
	} else {
		strlcat(fflags_string, "UNKNOWN", sizeof(fflags_string));
	}

	if (fflags_string[0] == '|')
		return &fflags_string[1];
	else
		return fflags_string;
}

char *str_kev_data(int filter, uint32_t fflags, int64_t data, uint64_t udata)
{
	static char data_string[128];

	if (filter == EVFILT_PROC) {
		if ((fflags & (NOTE_EXIT|NOTE_EXITSTATUS)) == (NOTE_EXIT|NOTE_EXITSTATUS)) {
			if (WIFEXITED(data)) {
				snprintf(data_string, sizeof(data_string), "pid %llu exited with status %d", udata, WEXITSTATUS(data));
			} else if (WIFSIGNALED(data)) {
				snprintf(data_string, sizeof(data_string), "pid %llu received signal %d%s", udata, WTERMSIG(data), WCOREDUMP(data) ? " (core dumped)" : "");
			} else if (WIFSTOPPED(data)) {
				snprintf(data_string, sizeof(data_string), "pid %llu stopped with signal %d", udata, WSTOPSIG(data));
			} else {
				snprintf(data_string, sizeof(data_string), "pid %llu unknown exit status 0x%08llx", udata, data);
			}
		} else if (fflags & NOTE_EXIT) {
			snprintf(data_string, sizeof(data_string), "pid %llu exited", udata);
		} else {
			data_string[0] = '\0';
		}
	} else if (filter == EVFILT_TIMER) {
		snprintf(data_string, sizeof(data_string), "timer fired %lld time(s)", data);
	} else {
		data_string[0] = '\0';
	}

	return data_string;
}

char *print_exit(pid_t p, int stat_loc)
{
	return str_kev_data(EVFILT_PROC, NOTE_EXIT|NOTE_EXITSTATUS, stat_loc, p);
}

bool iszombie(pid_t p)
{
	int ret;
	struct proc_bsdshortinfo bsdinfo;

	ret = proc_pidinfo(p, PROC_PIDT_SHORTBSDINFO, 1, &bsdinfo, sizeof(bsdinfo));
	if (ret != sizeof(bsdinfo)) {
		return false;
	}
		
	if (bsdinfo.pbsi_status == SZOMB) {
		return true;
	} else {
		return false;
	}
}
