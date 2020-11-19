#include <darwintest.h>
#include <darwintest_utils.h>
#include <crt_externs.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>

T_GLOBAL_META(
	T_META_RUN_CONCURRENTLY(true),
	T_META_LTEPHASE(LTE_POSTINIT)
	);

T_DECL(fd_invalid_pread, "Test for 66711697: make sure we get EFAULT")
{
	int fd;
	ssize_t rc;

	fd = open(*_NSGetProgname(), O_RDONLY);
	T_ASSERT_POSIX_SUCCESS(fd, "open(self)");

	rc = pread(fd, (void *)~0, 64 << 10, 0);
	T_ASSERT_POSIX_FAILURE(rc, EFAULT, "pread should fail with EFAULT");

	close(fd);
}
