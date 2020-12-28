#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <stdatomic.h>
#include <TargetConditionals.h>

#include <darwintest.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

static int nthreads = 0;
static int fd;
static _Atomic int phase = 0;
static _Atomic int pass_count = 0;
static _Atomic int fail_count = 0;

static void *
worker_thread_func(__unused void *arg)
{
	int myfd;
	int error;

	/* test racing shm_open */
	while (atomic_load(&phase) == 0) {
		;
	}
	myfd = shm_open("abcd", O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	if (myfd == -1) {
		T_QUIET; T_EXPECT_EQ(errno, EEXIST, "Expected EEXIST");
		atomic_fetch_add(&fail_count, 1);
	} else {
		fd = myfd;
		atomic_fetch_add(&pass_count, 1);
	}

	/* test racing ftruncate */
	while (atomic_load(&phase) == 1) {
		;
	}
	error = ftruncate(fd, 8 * 1024);
	if (error == -1) {
		T_QUIET; T_EXPECT_EQ(errno, EINVAL, "Expected EINVAL");
		atomic_fetch_add(&fail_count, 1);
	} else {
		atomic_fetch_add(&pass_count, 1);
	}

	/* test racing close */
	while (atomic_load(&phase) == 2) {
		;
	}
	error = close(fd);
	if (error == -1) {
		T_QUIET; T_EXPECT_EQ(errno, EBADF, "Expected EBADF");
		atomic_fetch_add(&fail_count, 1);
	} else {
		atomic_fetch_add(&pass_count, 1);
	}

	/* test racing shm_unlink() */
	while (atomic_load(&phase) == 3) {
		;
	}
	error = shm_unlink("abcd");
	if (error == -1) {
		T_QUIET; T_EXPECT_EQ(errno, ENOENT, "Expected ENOENT");
		atomic_fetch_add(&fail_count, 1);
	} else {
		atomic_fetch_add(&pass_count, 1);
	}
	return NULL;
}

static void
create_threads(void)
{
	int ret;
	int ncpu;
	size_t ncpu_size = sizeof(ncpu);
	int i;
	pthread_attr_t attr;

	ret = sysctlbyname("hw.ncpu", &ncpu, &ncpu_size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname(hw.ncpu)");

	T_QUIET; T_LOG("%s: Detected %d CPUs\n", __FUNCTION__, ncpu);

	nthreads = ncpu;
	T_QUIET; T_LOG("%s: Will create %d threads\n", __FUNCTION__, nthreads);

	ret = pthread_attr_init(&attr);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "pthread_attr_init");

	for (i = 0; i < nthreads; i++) {
		pthread_t thread;
		ret = pthread_create(&thread, &attr, worker_thread_func, NULL);
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "pthread_create");
	}
}


T_DECL(testposixshm, "Posix Shared Memory tests")
{
	int fd1;
	int fd2;
	int *addr;
	char *noname = "";
	char *toolong = "12345678901234567890123456789012";
	char *maxname = "1234567890123456789012345678901";

	/* must have O_CREAT */
	fd1 = shm_open(maxname, O_RDWR, S_IRUSR | S_IWUSR);
	T_EXPECT_EQ(fd1, -1, "shm_open() missing O_CREAT");
	T_WITH_ERRNO;
	T_EXPECT_EQ(errno, ENOENT, "Expected ENOENT");

	/* name too long */
	fd1 = shm_open(toolong, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	T_EXPECT_EQ(fd1, -1, "shm_open() name too long");
	T_WITH_ERRNO;
	T_EXPECT_EQ(errno, ENAMETOOLONG, "Expected ENAMETOOLONG");

	/* invalid name */
	fd1 = shm_open(noname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	T_EXPECT_EQ(fd1, -1, "shm_open() invalid name");
	T_WITH_ERRNO;
	T_EXPECT_EQ(errno, EINVAL, "Expected EINVAL");

	/* valid open */
	fd1 = shm_open(maxname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	T_EXPECT_POSIX_SUCCESS(fd1, "valid shm_open() result");

	/* O_CREAT, but not O_EXCL should work */
	fd2 = shm_open(maxname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	T_EXPECT_POSIX_SUCCESS(fd2, "shm_open() no O_EXCL");

	/* close should work */
	T_EXPECT_POSIX_ZERO(close(fd2), "close()");

	/* O_CREAT | O_EXCL should fail */
	fd2 = shm_open(maxname, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	T_WITH_ERRNO;
	T_EXPECT_EQ(fd2, -1, "shm_open() existing but O_EXCL");
	T_EXPECT_EQ(errno, EEXIST, "Expected EEXIST");

	/* use ftruncate to create the memory */
	T_EXPECT_POSIX_ZERO(ftruncate(fd1, 16 * 1024), NULL);

	/* a second ftruncate should fail */
	T_WITH_ERRNO;
	T_EXPECT_EQ(ftruncate(fd1, 8 * 1024), -1, "second ftruncate() should fail");
	T_EXPECT_EQ(errno, EINVAL, "Expected EINVAL");

	/* Map the memory object */
	addr = mmap(0, 4 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
	T_WITH_ERRNO;
	T_EXPECT_NE((void *)addr, MAP_FAILED, "mmap() should work");

	/* close should work */
	T_EXPECT_POSIX_ZERO(close(fd1), "close()");

	/* unlink should work */
	T_EXPECT_POSIX_SUCCESS(shm_unlink(maxname), "shm_unlink()");

	/* shm_open() after unlink/close should fail */
	fd2 = shm_open(maxname, O_RDWR, S_IRUSR | S_IWUSR);
	T_WITH_ERRNO;
	T_EXPECT_EQ(fd2, -1, "shm_open() but removed");
	T_EXPECT_EQ(errno, ENOENT, "Expected ENOENT");

	/*
	 * second phase of tests, try to create race conditions for
	 * shm_open() - multiple threads do shm_open(, ... O_EXCL, ...)
	 * ftruncate() - multiple threads, only 1 should succeed.
	 * fclose() - multiple threads, only 1 should succeed.
	 * shm_unlink() - multiple threads, only 1 should succeed.
	 */
	create_threads();
	sleep(1);
	T_LOG("Race testing shm_open");
	atomic_fetch_add(&phase, 1);
	while (pass_count + fail_count < nthreads) {
		sleep(1);
	}
	T_EXPECT_EQ(pass_count, 1, "racing shm_open()");
	T_EXPECT_EQ(fail_count, nthreads - 1, "racing shm_open()");

	atomic_store(&pass_count, 0);
	atomic_store(&fail_count, 0);
	T_LOG("Race testing ftruncate\n");
	atomic_fetch_add(&phase, 1);
	while (pass_count + fail_count < nthreads) {
		sleep(1);
	}
	T_EXPECT_EQ(pass_count, 1, "racing ftruncate()");
	T_EXPECT_EQ(fail_count, nthreads - 1, "racing ftruncate()");

	atomic_store(&pass_count, 0);
	atomic_store(&fail_count, 0);
	T_LOG("Race testing fclose\n");
	atomic_fetch_add(&phase, 1);
	while (pass_count + fail_count < nthreads) {
		sleep(1);
	}
	T_EXPECT_EQ(pass_count, 1, "racing fclose()");
	T_EXPECT_EQ(fail_count, nthreads - 1, "racing fclose()");

	atomic_store(&pass_count, 0);
	atomic_store(&fail_count, 0);
	T_LOG("Race testing shm_unlink\n");
	atomic_fetch_add(&phase, 1);
	while (pass_count + fail_count < nthreads) {
		sleep(1);
	}
	T_EXPECT_EQ(pass_count, 1, "racing shm_unlink()");
	T_EXPECT_EQ(fail_count, nthreads - 1, "racing shm_unlink()");
}
