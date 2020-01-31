#include "ramdisk.h"
#include "fail.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/param.h>

int
setup_ram_volume(const char* name, char* path)
{
	char *cmd;
	int retval;

	retval = asprintf(&cmd, "diskutil erasevolume HFS+ '%s' `hdiutil attach -nomount ram://1500000` >/dev/null", name);
	VERIFY(retval > 0, "asprintf failed");

	retval = system(cmd);
	VERIFY(retval == 0, "diskutil command failed");

	snprintf(path, MAXPATHLEN, "/Volumes/%s", name);

	free(cmd);

	return PERFINDEX_SUCCESS;
}

int
cleanup_ram_volume(char* path)
{
	char *cmd;
	int retval;

	retval = asprintf(&cmd, "umount -f '%s' >/dev/null", path);
	VERIFY(retval > 0, "asprintf failed");

	retval = system(cmd);
	VERIFY(retval == 0, "diskutil command failed");

	free(cmd);

	return PERFINDEX_SUCCESS;
}
