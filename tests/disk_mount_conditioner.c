#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif
#include <darwintest.h>
#include <darwintest_utils.h>

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <System/sys/fsctl.h>
#include <paths.h>

static char *mktempdir(void);
static char *mktempmount(void);

#ifndef TEST_UNENTITLED
static int system_legal(const char *command);
static char *mkramdisk(void);
static uint64_t time_for_read(int fd, const char *expected);
static void perf_setup(char **path, int *fd);

#define READSIZE 1024L
#endif /* !TEST_UNENTITLED */

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vfs.dmc"),
	T_META_ASROOT(true)
);

#pragma mark Entitled Tests

#ifndef TEST_UNENTITLED
T_DECL(fsctl_get_uninitialized,
	"Initial fsctl.get should return zeros",
	T_META_ASROOT(false))
{
	int err;
	char *mount_path;
	disk_conditioner_info info = {0};
	disk_conditioner_info expected_info = {0};

	T_SETUPBEGIN;
	mount_path = mktempmount();
	T_SETUPEND;

	info.enabled = true;
	info.is_ssd = true;
	err = fsctl(mount_path, DISK_CONDITIONER_IOC_GET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl(DISK_CONDITIONER_IOC_GET)");

	err = memcmp(&info, &expected_info, sizeof(info));
	T_ASSERT_EQ_INT(0, err, "initial DMC info is zeroed");
}

T_DECL(fsctl_set,
	"fsctl.set should succeed and fsctl.get should verify")
{
	int err;
	char *mount_path;
	disk_conditioner_info info = {0};
	disk_conditioner_info expected_info = {0};

	T_SETUPBEGIN;
	mount_path = mktempmount();
	T_SETUPEND;

	info.enabled = 1;
	info.access_time_usec = 10;
	info.read_throughput_mbps = 40;
	info.write_throughput_mbps = 40;
	info.is_ssd = 0;
	info.ioqueue_depth = 8;
	info.maxreadcnt = 8;
	info.maxwritecnt = 8;
	info.segreadcnt = 8;
	info.segwritecnt = 8;
	expected_info = info;

	err = fsctl(mount_path, DISK_CONDITIONER_IOC_SET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl(DISK_CONDITIONER_IOC_SET)");

	err = fsctl(mount_path, DISK_CONDITIONER_IOC_GET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl(DISK_CONDITIONER_IOC_GET) after SET");

	err = memcmp(&info, &expected_info, sizeof(info));
	T_ASSERT_EQ_INT(0, err, "fsctl.get is the info configured by fsctl.set");
}

static void
verify_mount_fallback_values(const char *mount_path, disk_conditioner_info *info)
{
	int err;
	disk_conditioner_info newinfo = {0};

	err = fsctl(mount_path, DISK_CONDITIONER_IOC_SET, info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl(DISK_CONDITIONER_IOC_SET)");

	err = fsctl(mount_path, DISK_CONDITIONER_IOC_GET, &newinfo, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl(DISK_CONDITIONER_IOC_GET) after SET");

	// without querying the drive for the expected values, the best we can do is
	// assert that they are not zero (impossible) or less than UINT32_MAX (unlikely)
	T_ASSERT_GT(newinfo.ioqueue_depth, 0u, "ioqueue_depth is the value from the mount");
	T_ASSERT_GT(newinfo.maxreadcnt, 0u, "maxreadcnt is value from the mount");
	T_ASSERT_GT(newinfo.maxwritecnt, 0u, "maxwritecnt is value from the mount");
	T_ASSERT_GT(newinfo.segreadcnt, 0u, "segreadcnt is value from the mount");
	T_ASSERT_GT(newinfo.segwritecnt, 0u, "segwritecnt is value from the mount");
	T_ASSERT_LT(newinfo.ioqueue_depth, UINT32_MAX, "ioqueue_depth is the value from the mount");
	T_ASSERT_LT(newinfo.maxreadcnt, UINT32_MAX, "maxreadcnt is value from the mount");
	T_ASSERT_LT(newinfo.maxwritecnt, UINT32_MAX, "maxwritecnt is value from the mount");
	T_ASSERT_LT(newinfo.segreadcnt, UINT32_MAX, "segreadcnt is value from the mount");
	T_ASSERT_LT(newinfo.segwritecnt, UINT32_MAX, "segwritecnt is value from the mount");
}

T_DECL(fsctl_set_zero,
	"fsctl.set zero values should fall back to original mount settings")
{
	char *mount_path;
	disk_conditioner_info info = {0};

	T_SETUPBEGIN;
	mount_path = mktempmount();

	info.enabled = 1;
	/* everything else is 0 */

	T_SETUPEND;

	verify_mount_fallback_values(mount_path, &info);
}

T_DECL(fsctl_set_out_of_bounds,
	"fsctl.set out-of-bounds values should fall back to original mount settings")
{
	char *mount_path;
	disk_conditioner_info info;

	T_SETUPBEGIN;
	mount_path = mktempmount();

	memset(&info, UINT32_MAX, sizeof(info));
	info.enabled = 1;
	info.access_time_usec = 0;
	info.read_throughput_mbps = 0;
	info.write_throughput_mbps = 0;
	/* everything else is UINT32_MAX */

	T_SETUPEND;

	verify_mount_fallback_values(mount_path, &info);
}

T_DECL(fsctl_restore_mount_fields,
	"fsctl.set should restore fields on mount_t that it temporarily overrides")
{
	int err;
	char *mount_path;
	disk_conditioner_info info;
	disk_conditioner_info mount_fields;

	T_SETUPBEGIN;
	mount_path = mktempmount();
	T_SETUPEND;

	/* first set out-of-bounds values to retrieve the original mount_t fields */
	memset(&info, UINT32_MAX, sizeof(info));
	info.enabled = 1;
	info.access_time_usec = 0;
	info.read_throughput_mbps = 0;
	info.write_throughput_mbps = 0;
	/* everything else is UINT32_MAX */
	err = fsctl(mount_path, DISK_CONDITIONER_IOC_SET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl(DISK_CONDITIONER_IOC_SET)");

	err = fsctl(mount_path, DISK_CONDITIONER_IOC_GET, &mount_fields, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl(DISK_CONDITIONER_IOC_GET)");

	/* now turn off the disk conditioner which should restore fields on the mount_t */
	memset(&info, 1, sizeof(info));
	info.enabled = 0;
	err = fsctl(mount_path, DISK_CONDITIONER_IOC_SET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl(DISK_CONDITIONER_IOC_SET)");

	/* and finally set out-of-bounds values again to retrieve the new mount_t fields which should not have changed */
	memset(&info, UINT32_MAX, sizeof(info));
	info.enabled = 0;
	info.access_time_usec = 0;
	info.read_throughput_mbps = 0;
	info.write_throughput_mbps = 0;
	/* everything else is UINT32_MAX */
	err = fsctl(mount_path, DISK_CONDITIONER_IOC_SET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl(DISK_CONDITIONER_IOC_SET)");

	err = fsctl(mount_path, DISK_CONDITIONER_IOC_GET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl(DISK_CONDITIONER_IOC_GET)");

	T_ASSERT_EQ(info.maxreadcnt, mount_fields.maxreadcnt, "mount_t maxreadcnt restored");
	T_ASSERT_EQ(info.maxwritecnt, mount_fields.maxwritecnt, "mount_t maxwritecnt restored");
	T_ASSERT_EQ(info.segreadcnt, mount_fields.segreadcnt, "mount_t segreadcnt restored");
	T_ASSERT_EQ(info.segwritecnt, mount_fields.segwritecnt, "mount_t segwritecnt restored");
	T_ASSERT_EQ(info.ioqueue_depth, mount_fields.ioqueue_depth, "mount_t ioqueue_depth restored");
}

T_DECL(fsctl_get_nonroot,
	"fsctl.get should not require root",
	T_META_ASROOT(false))
{
	int err;
	char *mount_path;
	disk_conditioner_info info;

	T_SETUPBEGIN;
	// make sure we're not root
	if (0 == geteuid()) {
		seteuid(5000);
	}

	mount_path = mktempmount();
	T_SETUPEND;

	err = fsctl(mount_path, DISK_CONDITIONER_IOC_GET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl.get without root");
}

T_DECL(fsctl_set_nonroot,
	"fsctl.set should require root",
	T_META_ASROOT(false))
{
	int err;
	char *mount_path;
	disk_conditioner_info info = {0};
	disk_conditioner_info expected_info = {0};

	T_SETUPBEGIN;
	// make sure we're not root
	if (0 == geteuid()) {
		seteuid(5000);
	}

	mount_path = mktempmount();
	T_SETUPEND;

	// save original info
	err = fsctl(mount_path, DISK_CONDITIONER_IOC_GET, &expected_info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "Get original DMC info");

	info.enabled = 1;
	info.access_time_usec = 10;
	err = fsctl(mount_path, DISK_CONDITIONER_IOC_SET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_NE_INT(0, err, "fsctl.set returns error without root");

	err = fsctl(mount_path, DISK_CONDITIONER_IOC_GET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl.get after nonroot fsctl.set");

	err = memcmp(&info, &expected_info, sizeof(info));
	T_ASSERT_EQ_INT(0, err, "fsctl.set should not change info without root");
}

T_DECL(fsctl_delays,
	"Validate I/O delays when DMC is enabled")
{
	char *path;
	int fd;
	int err;
	uint64_t elapsed_nsec, expected_nsec;
	disk_conditioner_info info = {0};
	char buf[READSIZE];

	T_SETUPBEGIN;
	perf_setup(&path, &fd);
	memset(buf, 0xFF, sizeof(buf));
	T_ASSERT_EQ_LONG((long)sizeof(buf), write(fd, buf, sizeof(buf)), "write random data to temp file");
	fcntl(fd, F_FULLFSYNC);
	T_SETUPEND;

	expected_nsec = NSEC_PER_SEC / 2;

	// measure delay before setting parameters (should be none)
	elapsed_nsec = time_for_read(fd, buf);
	T_ASSERT_LT_ULLONG(elapsed_nsec, expected_nsec, "DMC disabled read(%ld) from %s is reasonably fast", READSIZE, path);

	// measure delay after setting parameters
	info.enabled = 1;
	info.access_time_usec = expected_nsec / NSEC_PER_USEC;
	info.read_throughput_mbps = 40;
	info.write_throughput_mbps = 40;
	info.is_ssd = 1; // is_ssd will ensure we get constant access_time delays rather than scaled
	err = fsctl(path, DISK_CONDITIONER_IOC_SET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl(DISK_CONDITIONER_IOC_SET) delay");

	elapsed_nsec = time_for_read(fd, buf);
	T_ASSERT_GT_ULLONG(elapsed_nsec, expected_nsec, "DMC enabled read(%ld) from %s is at least the expected delay", READSIZE, path);
	T_ASSERT_LT_ULLONG(elapsed_nsec, 2 * expected_nsec, "DMC enabled read(%ld) from %s is no more than twice the expected delay", READSIZE, path);

	// measure delay after resetting parameters (should be none)
	info.enabled = 0;
	err = fsctl(path, DISK_CONDITIONER_IOC_SET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl(DISK_CONDITIONER_IOC_SET) reset delay");

	usleep(USEC_PER_SEC / 2); // might still be other I/O inflight
	elapsed_nsec = time_for_read(fd, buf);
	T_ASSERT_LT_ULLONG(elapsed_nsec, expected_nsec, "After disabling DMC read(%ld) from %s is reasonably fast", READSIZE, path);
}

#else /* TEST_UNENTITLED */

#pragma mark Unentitled Tests

T_DECL(fsctl_get_unentitled,
	"fsctl.get should not require entitlement")
{
	int err;
	char *mount_path;
	disk_conditioner_info info;

	T_SETUPBEGIN;
	mount_path = mktempmount();
	T_SETUPEND;

	err = fsctl(mount_path, DISK_CONDITIONER_IOC_GET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl.get without entitlement");
}

T_DECL(fsctl_set_unentitled,
	"fsctl.set should require entitlement")
{
	int err;
	char *mount_path;
	disk_conditioner_info info = {0};
	disk_conditioner_info expected_info = {0};

	T_SETUPBEGIN;
	mount_path = mktempmount();
	T_SETUPEND;

	// save original info
	err = fsctl(mount_path, DISK_CONDITIONER_IOC_GET, &expected_info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "Get original DMC info");

	info.enabled = 1;
	info.access_time_usec = 10;
	err = fsctl(mount_path, DISK_CONDITIONER_IOC_SET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_NE_INT(0, err, "fsctl.set returns error without entitlement");

	err = fsctl(mount_path, DISK_CONDITIONER_IOC_GET, &info, 0);
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, err, "fsctl.get after unentitled fsctl.set");

	err = memcmp(&info, &expected_info, sizeof(info));
	T_ASSERT_EQ_INT(0, err, "fsctl.set should not change info without entitlement");
}

#endif /* TEST_UNENTITLED */

#pragma mark Helpers

static char *mktempdir(void) {
	char *path = malloc(PATH_MAX);
	strcpy(path, "/tmp/dmc.XXXXXXXX");
	atexit_b(^{ free(path); });

	// create a temporary mount to run the fsctl on
	T_WITH_ERRNO;
	T_ASSERT_NOTNULL(mkdtemp(path), "Create temporary directory");
	atexit_b(^{ remove(path); });

	return path;
}

/*
 * Return the path to a temporary mount
 * with no usable filesystem but still
 * can be configured by the disk conditioner
 *
 * Faster than creating a ram disk to test with
 * when access to the filesystem is not necessary
 */
static char *mktempmount(void) {
	char *mount_path = mktempdir();

	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(0, mount("devfs", mount_path, MNT_RDONLY, NULL), "Create temporary devfs mount");
	atexit_b(^{ unmount(mount_path, MNT_FORCE); });

	return mount_path;
}

#ifndef TEST_UNENTITLED

/*
 * Wrapper around dt_launch_tool/dt_waitpid
 * that works like libc:system()
 */
static int system_legal(const char *command) {
	pid_t pid = -1;
	int exit_status = 0;
	const char *argv[] = {
		_PATH_BSHELL,
		"-c",
		command,
		NULL
	};

	int rc = dt_launch_tool(&pid, (char **)(void *)argv, false, NULL, NULL);
	if (rc != 0) {
		return -1;
	}
	if (!dt_waitpid(pid, &exit_status, NULL, 30)) {
		if (exit_status != 0) {
			return exit_status;
		}
		return -1;
	}

	return exit_status;
}

/*
 * Return the path to a temporary mount
 * that contains a usable HFS+ filesystem
 * mounted via a ram disk
 */
static char *mkramdisk(void) {
	char cmd[1024];
	char *mount_path = mktempdir();
	char *dev_disk_file = malloc(256);
	atexit_b(^{ free(dev_disk_file); });
	strcpy(dev_disk_file, "/tmp/dmc.ramdisk.XXXXXXXX");

	T_WITH_ERRNO;
	T_ASSERT_NOTNULL(mktemp(dev_disk_file), "Create temporary file to store dev disk for ramdisk");
	atexit_b(^{ remove(dev_disk_file); });

	// create the RAM disk device
	snprintf(cmd, sizeof(cmd), "hdik -nomount ram://10000 > %s", dev_disk_file);
	T_ASSERT_EQ_INT(0, system_legal(cmd), "Create ramdisk");

	atexit_b(^{
		char eject_cmd[1024];
		unmount(mount_path, MNT_FORCE);
		snprintf(eject_cmd, sizeof(eject_cmd), "hdik -e `cat %s`", dev_disk_file);
		system_legal(eject_cmd);
		remove(dev_disk_file);
	});

	// initialize as an HFS volume
	snprintf(cmd, sizeof(cmd), "newfs_hfs `cat %s`", dev_disk_file);
	T_ASSERT_EQ_INT(0, system_legal(cmd), "Initialize ramdisk as HFS");

	// mount it
	snprintf(cmd, sizeof(cmd), "mount -t hfs `cat %s` %s", dev_disk_file, mount_path);
	T_ASSERT_EQ_INT(0, system_legal(cmd), "Mount ramdisk");

	return mount_path;
}

static uint64_t time_for_read(int fd, const char *expected) {
	int err;
	ssize_t ret;
	char buf[READSIZE];
	uint64_t start, stop;

	bzero(buf, sizeof(buf));
	lseek(fd, 0, SEEK_SET);

	start = dt_nanoseconds();
	ret = read(fd, buf, READSIZE);
	stop = dt_nanoseconds();

	T_ASSERT_GE_LONG(ret, 0L, "read from temporary file");
	T_ASSERT_EQ_LONG(ret, READSIZE, "read %ld bytes from temporary file", READSIZE);
	err = memcmp(buf, expected, sizeof(buf));
	T_ASSERT_EQ_INT(0, err, "read expected contents from temporary file");

	return (stop - start);
}

static void perf_setup(char **path, int *fd) {
	int temp_fd;
	char *temp_path;

	char *mount_path = mkramdisk();
	temp_path = *path = malloc(PATH_MAX);
	snprintf(temp_path, PATH_MAX, "%s/dmc.XXXXXXXX", mount_path);
	atexit_b(^{ free(temp_path); });

	T_ASSERT_NOTNULL(mktemp(temp_path), "Create temporary file");
	atexit_b(^{ remove(temp_path); });

	temp_fd = *fd = open(temp_path, O_RDWR | O_CREAT);
	T_WITH_ERRNO;
	T_ASSERT_GE_INT(temp_fd, 0, "Open temporary file for read/write");
	atexit_b(^{ close(temp_fd); });
	fcntl(temp_fd, F_NOCACHE, 1);
}
#endif /* !TEST_UNENTITLED */
