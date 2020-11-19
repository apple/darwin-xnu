#include <stdio.h>
#include <unistd.h>
#include <spawn.h>
#include <spawn_private.h>
#include <sys/sysctl.h>

extern char **environ;

#ifndef _POSIX_SPAWN_FORCE_4K_PAGES
#define _POSIX_SPAWN_FORCE_4K_PAGES 0x1000
#endif /* _POSIX_SPAWN_FORCE_4K_PAGES */

int
main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s </path/to/command> [<arg> ..]\n", argv[0]);
		return 1;
	}

	char * prog_path = argv[1];
	if (0 != access(prog_path, X_OK)) {
		fprintf(stderr, "%s is not an executable\n", prog_path);
		return 1;
	}

	pid_t newpid = 0;
	posix_spawn_file_actions_t fileactions;
	posix_spawnattr_t spawnattrs;
	if (posix_spawnattr_init(&spawnattrs)) {
		perror("posix_spawnattr_init");
		return 1;
	}
	if (posix_spawn_file_actions_init(&fileactions)) {
		perror("posix_spawn_file_actions_init");
		return 1;
	}
	short sp_flags = POSIX_SPAWN_SETEXEC;

	/* Need to set special flags */
	int supported = 0;
	size_t supported_size = sizeof(supported);

	int r = sysctlbyname("debug.vm_mixed_pagesize_supported", &supported, &supported_size, NULL, 0);
	if (r == 0 && supported) {
		sp_flags |= _POSIX_SPAWN_FORCE_4K_PAGES;
	} else {
		/*
		 * We didnt find debug.vm.mixed_page.supported OR its set to 0.
		 * Skip the test.
		 */
		printf("Hardware doesn't support 4K pages, skipping test...");
		return 0;
	}

	posix_spawnattr_setflags(&spawnattrs, sp_flags);
	posix_spawn(&newpid, prog_path, &fileactions, &spawnattrs, &argv[1], environ);

	/* Should not have reached here */
	fprintf(stderr, "should not have reached here");
	return 1;
}
