/*
 * spawn_persona.c
 * Use new POSIX spawn attributes to create a new process in a persona
 *
 * Jeremy C. Andrus <jeremy_andrus@apple.com>
 *
 */
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/vm_param.h>
#include <sys/kauth.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include "persona_test.h"

/* internal */
#include <libproc.h>
#include <spawn_private.h>
#include <sys/persona.h>
#include <sys/proc_info.h>
#include <sys/spawn_internal.h>

#define PERSONA_TEST_NAME   "Persona Spawn"
#define PERSONA_TEST_VMAJOR 0
#define PERSONA_TEST_VMINOR 1

static struct test_config {
	int verbose;
	int wait_for_children;
} g;


/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 *
 * Child Management
 *
 * = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 */
struct child {
	TAILQ_ENTRY(child) sibling;
	int pid;
};

static pthread_mutex_t g_child_mtx;
static TAILQ_HEAD(, child) g_children = TAILQ_HEAD_INITIALIZER(g_children);
static int g_nchildren = 0;

static pid_t
spawn_child(int argc, char **argv, struct persona_args *pa)
{
	int ret;
	uint32_t persona_flags = 0;
	posix_spawnattr_t attr;
	struct child *child = NULL;
	extern char **environ;

	(void)argc;

	if (!pa) {
		err_print("Invalid persona args!");
		return -ERR_SYSTEM;
	}

	if (!(pa->flags & PA_HAS_ID)) {
		err_print("No persona ID specified!");
		return -ERR_SYSTEM;
	}

	if (g.verbose) {
		dump_persona_args("Spawning new child with args: ", pa);
		infov("\t prog: \"%s\"", argv[0]);
		for (int i = 1; i < argc; i++) {
			infov("\t arg[%d]: %s", i, argv[i]);
		}
	}

	child = (struct child *)calloc(1, sizeof(*child));
	if (!child) {
		err_print("No memory left :-(");
		return -ERR_SYSTEM;
	}

	ret = posix_spawnattr_init(&attr);
	if (ret != 0) {
		err_print("posix_spawnattr_init");
		ret = -ERR_SPAWN_ATTR;
		goto out_err;
	}

	if (pa->flags & PA_SHOULD_VERIFY) {
		persona_flags |= POSIX_SPAWN_PERSONA_FLAGS_VERIFY;
	}

	if (pa->flags & PA_OVERRIDE) {
		persona_flags |= POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE;
	}

	ret = posix_spawnattr_set_persona_np(&attr, pa->kinfo.persona_id, persona_flags);
	if (ret != 0) {
		err_print("posix_spawnattr_set_persona_np failed!");
		ret = -ERR_SPAWN_ATTR;
		goto out_err;
	}

	if (pa->flags & PA_HAS_UID) {
		ret = posix_spawnattr_set_persona_uid_np(&attr, pa->override_uid);
		if (ret != 0) {
			err_print("posix_spawnattr_set_persona_uid_np failed!");
			ret = -ERR_SPAWN_ATTR;
			goto out_err;
		}
	}

	if (pa->flags & PA_HAS_GID) {
		ret = posix_spawnattr_set_persona_gid_np(&attr, pa->kinfo.persona_gid);
		if (ret != 0) {
			err_print("posix_spawnattr_set_persona_gid_np failed!");
			ret = -ERR_SPAWN_ATTR;
			goto out_err;
		}
	}

	if (pa->flags & PA_HAS_GROUPS) {
		ret = posix_spawnattr_set_persona_groups_np(&attr, pa->kinfo.persona_ngroups, pa->kinfo.persona_groups, KAUTH_UID_NONE);
		if (ret != 0) {
			err_print("");
			ret = -ERR_SPAWN_ATTR;
			goto out_err;
		}
	}

	ret = posix_spawn(&child->pid, argv[0], NULL, &attr, argv, environ);
	if (ret != 0) {
		err_print("posix_spawn (ret=%d)", ret);
		ret = -ERR_SPAWN;
		goto out_err;
	}

	infov("\tspawned child PID: %d", child->pid);

	/* link the processes onto the global children list */
	pthread_mutex_lock(&g_child_mtx);
	TAILQ_INSERT_TAIL(&g_children, child, sibling);
	++g_nchildren;
	pthread_mutex_unlock(&g_child_mtx);

	posix_spawnattr_destroy(&attr);
	return child->pid;

out_err:
	posix_spawnattr_destroy(&attr);
	free(child);
	return (pid_t)ret;
}


static int child_should_exit = 0;

static void
child_sighandler(int sig)
{
	(void)sig;
	dbg("PID: %d received sig %d", getpid(), sig);
	child_should_exit = 1;
}

static int
child_main_loop(int argc, char **argv)
{
	char ch;
	sigset_t sigset;
	int err = 0;
	uid_t persona_id = 0;
	struct kpersona_info kinfo;
	int rval = 0;

	while ((ch = getopt(argc, argv, "vhER")) != -1) {
		switch (ch) {
		case 'v':
			g.verbose = 1;
			break;
		case 'E':
			child_should_exit = 1;
			break;
		case 'R':
			rval = 1;
			break;
		case 'h':
		case '?':
		case ':':
		default:
			err("Invalid child process invocation.");
		}
	}

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGHUP);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGABRT);
	sigaddset(&sigset, SIGCHLD);
	sigprocmask(SIG_UNBLOCK, &sigset, NULL);

	signal(SIGINT, child_sighandler);
	signal(SIGHUP, child_sighandler);
	signal(SIGTERM, child_sighandler);
	signal(SIGABRT, child_sighandler);
	signal(SIGCHLD, child_sighandler);

	err = kpersona_get(&persona_id);

	info("Child: PID:%d", getpid());
	info("Child: UID:%d, GID:%d", getuid(), getgid());
	info("Child: login:%s", getlogin());
	info("Child: Persona: %d (err:%d)", persona_id, err);

	kinfo.persona_info_version = PERSONA_INFO_V1;
	err = kpersona_info(persona_id, &kinfo);
	if (err == 0) {
		dump_kpersona("Child: kpersona_info", &kinfo);
	} else {
		info("Child: ERROR grabbing kpersona_info: %d", errno);
	}

	if (child_should_exit) {
		return rval;
	}

	infov("Child Sleeping!");
	while (!child_should_exit) {
		sleep(1);
	}

	infov("Child exiting!");
	return rval;
}


/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 *
 * Main Entry Point
 *
 * = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 */
static void
main_sighandler(int sig)
{
	dbg("PID: %d received sig %d", getpid(), sig);
	if (sig == SIGCHLD) {
		--g_nchildren;
	}
}

static void
usage_main(const char *progname, int verbose)
{
	const char *nm = basename((char *)progname);

	printf("%s v%d.%d\n", PERSONA_TEST_NAME, PERSONA_TEST_VMAJOR, PERSONA_TEST_VMINOR);
	printf("usage: %s [-I id] [-V] [-u uid] [-g gid] [-vw] progname [args...]\n", nm);
	printf("       Spawn a new process into a new or existing persona.\n");
	if (!verbose) {
		exit(1);
	}

	printf("\t%-10s\tID of the persona\n", "-I id");
	printf("\t%-10s\tVerify persona parameters against existing persona (given by -I)\n", "-V");
	printf("\t%-10s\tOverride/verify the user ID of the new process\n", "-u uid");
	printf("\t%-10s\tOverride/verify the group ID of the new process\n", "-g gid");
	printf("\t%-15s\tGroups to which the persona will belong\n", "-G {groupspec}");
	printf("\t%-15s\tgroupspec: G1{,G2,G3...}\n", " ");
	printf("\t%-10s\tBe verbose\n", "-v");
	printf("\t%-10s\tDo not wait for the child process\n", "-w");
	printf("\n");

	exit(1);
}

int
main(int argc, char **argv)
{
	char ch;
	int ret;

	pthread_mutex_init(&g_child_mtx, NULL);

	/*
	 * Defaults
	 */
	g.verbose = 0;
	g.wait_for_children = 1;

	if (argc > 1 && strcmp(argv[1], "child") == 0) {
		optind = 2;
		ret = child_main_loop(argc, argv);
		if (ret != 1) {
			exit(ret);
		}
		if (strcmp(argv[optind], "spawn") != 0) {
			printf("child exiting (%s).\n", argv[optind]);
			exit(0);
		}
		optind++;

		/*
		 * If we get here, then the child wants us to continue running
		 * to potentially spawn yet another child process. This is
		 * helpful when testing inherited personas and verifying
		 * persona restrictions.
		 */
	}

	if (geteuid() != 0) {
		err("%s must be run as root", argv[0] ? basename(argv[0]) : PERSONA_TEST_NAME);
	}

	struct persona_args pa;
	memset(&pa, 0, sizeof(pa));

	pa.flags = PA_NONE;
	pa.kinfo.persona_id = getuid();

	/*
	 * Argument parse for default overrides:
	 */
	while ((ch = getopt(argc, argv, "Vg:G:I:u:vwh")) != -1) {
		switch (ch) {
		case 'V':
			pa.flags |= PA_SHOULD_VERIFY;
			break;
		case 'g':
			pa.kinfo.persona_gid = atoi(optarg);
			pa.flags |= PA_HAS_GID;
			pa.flags |= PA_OVERRIDE;
			break;
		case 'G':
			ret = parse_groupspec(&pa.kinfo, optarg);
			if (ret < 0) {
				err("Invalid groupspec: \"%s\"", optarg);
			}
			pa.flags |= PA_HAS_GROUPS;
			pa.flags |= PA_OVERRIDE;
			break;
		case 'I':
			pa.kinfo.persona_id = atoi(optarg);
			if (pa.kinfo.persona_id == 0) {
				err("Invalid Persona ID: %s", optarg);
			}
			pa.flags |= PA_HAS_ID;
			break;
		case 'u':
			pa.override_uid = atoi(optarg);
			pa.flags |= PA_HAS_UID;
			pa.flags |= PA_OVERRIDE;
			break;
		case 'v':
			g.verbose = 1;
			break;
		case 'w':
			g.wait_for_children = 0;
			break;
		case 'h':
		case '?':
			usage_main(argv[0], 1);
		case ':':
		default:
			printf("Invalid option: '%c'\n", ch);
			usage_main(argv[0], 0);
		}
	}

	if (pa.flags & PA_SHOULD_VERIFY) {
		pa.flags = ~PA_OVERRIDE;
	}

	if (optind >= argc) {
		printf("No program given!\n");
		usage_main(argv[0], 0);
	}

	argc -= optind;
	for (int i = 0; i < argc; i++) {
		argv[i] = argv[i + optind];
	}

	argv[argc] = NULL;

	ret = spawn_child(argc, argv, &pa);
	if (ret < 0) {
		return ret;
	}

	pid_t child_pid = (pid_t)ret;
	int status = 0;
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGCHLD);
	sigprocmask(SIG_UNBLOCK, &sigset, NULL);
	signal(SIGCHLD, main_sighandler);

	if (g.wait_for_children) {
		infov("Waiting for child...");
		waitpid(child_pid, &status, 0);
		if (WIFEXITED(status)) {
			status = WEXITSTATUS(status);
			if (status != 0) {
				errc(ERR_CHILD_FAIL,
				    "Child exited with status: %d", status);
			}
		}
	}

	info("Done.");
	return 0;
}
