#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>

#define SUBSYSTEM_ROOT_PATH_KEY "subsystem_root_path"

#define HELPER_BEHAVIOR_NOT_SET    "not_set"
#define HELPER_BEHAVIOR_SET        "set"
#define HELPER_BEHAVIOR_FORK_EXEC  "fork_exec"
#define HELPER_BEHAVIOR_SPAWN      "spawn"

static int
_spawn_and_wait(char ** args, posix_spawnattr_t *attr)
{
	int pid;
	int status;

	if (posix_spawn(&pid, args[0], NULL, attr, args, NULL)) {
		return -1;
	}
	if (waitpid(pid, &status, 0) < 0) {
		return -1;
	}

	if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
		return 0;
	}

	return -1;
}
