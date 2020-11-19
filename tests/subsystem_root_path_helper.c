#include <string.h>
#include <spawn_private.h>
#include <_simple.h>
#include "subsystem_root_path.h"

int
main(int argc, char **argv, char **env, const char **apple)
{
	int retval = 0;

	if (argc != 3) {
		return 1;
	}

	char * behavior = argv[1];
	char * expected_subsystem_root_path = argv[2];

	if (!strcmp(behavior, HELPER_BEHAVIOR_SET)) {
		const char * subsystem_root_path = _simple_getenv(apple, SUBSYSTEM_ROOT_PATH_KEY);
		if (strcmp(subsystem_root_path, expected_subsystem_root_path)) {
			retval = 1;
		}
	} else if (!strcmp(behavior, HELPER_BEHAVIOR_NOT_SET)) {
		const char * subsystem_root_path = _simple_getenv(apple, SUBSYSTEM_ROOT_PATH_KEY);
		if (subsystem_root_path != NULL) {
			retval = 1;
		}
	} else if (!strcmp(behavior, HELPER_BEHAVIOR_FORK_EXEC)) {
		int pid = fork();

		if (pid > 0) {
			/* Parent */
			int status;
			if (waitpid(pid, &status, 0) < 0) {
				retval = 1;
			}

			if (!(WIFEXITED(status) && (WEXITSTATUS(status) == 0))) {
				retval = 1;
			}
		} else if (pid == 0) {
			/* Child */
			char *new_argv[] = {argv[0], HELPER_BEHAVIOR_SET, argv[2], NULL};
			execv(new_argv[0], new_argv);
			retval = 1;
		} else if (pid < 0) {
			/* Failed */
			retval = 1;
		}
	} else if (!strcmp(behavior, HELPER_BEHAVIOR_SPAWN)) {
		char * new_argv[] = {argv[0], HELPER_BEHAVIOR_SET, "/helper_root/", NULL};
		posix_spawnattr_t attr;
		posix_spawnattr_init(&attr);
		posix_spawnattr_set_subsystem_root_path_np(&attr, new_argv[2]);
		retval = _spawn_and_wait(new_argv, &attr);
		posix_spawnattr_destroy(&attr);
	}

	return retval;
}
