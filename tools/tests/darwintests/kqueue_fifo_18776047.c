/*
 * testname: kqueue_fifo
 */

#include <darwintest.h>
#include <fcntl.h>
#include <sys/event.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#define TMP_FILE_PATH "/tmp/test_kqueue_fifo_18776047"

#define READ_BUFFER_LEN 256

#if defined(PLATFORM_WatchOS)
#define TOTAL_ITERATIONS 5000
#else
#define TOTAL_ITERATIONS 10000
#endif

/* prototypes */
int write_some_data(int fd);
int read_data(int fd);
void create_fifo(const char * filepath);
void kevent_one_shot(int kq, int fd, int filter);

int
write_some_data(int fd)
{
	int retval  = 0;
	int count   = 0;
	int len     = 5;
	char * data = "ABCDE";
	while (true) {
		errno  = 0;
		retval = (int)write(fd, data, (size_t)len);
		if (retval < 0) {
			if (errno == EAGAIN) {
				if (len == 1)
					return count;
				else
					len--;
			} else {
				T_ASSERT_FAIL("write to fd %d of %s of len %d failed.", fd, data, len);
				abort();
			}
		} else {
			count += retval;
		}
	}
}

int
read_data(int fd)
{
	int retval, count = 0;
	char databuffer[READ_BUFFER_LEN];
	while (true) {
		errno  = 0;
		retval = (int)read(fd, databuffer, READ_BUFFER_LEN);
		if (retval < 0) {
			if (errno == EAGAIN) {
				return count;
			} else {
				T_ASSERT_FAIL("read from fd %d failed.", fd);
				abort();
			}
		}
		count += retval;
	}
}

void
create_fifo(const char * filepath)
{
	struct stat f_stat;
	int ret = 0;
	errno   = 0;
	ret = stat(filepath, &f_stat);
	if (ret == 0) {
		/* if file exists, make sure its a fifo */
		T_ASSERT_TRUE(S_ISFIFO(f_stat.st_mode), "ensure %s is a fifo", filepath);
	} else if (errno == ENOENT) {
		ret = mkfifo(filepath, 0777);
		T_ASSERT_POSIX_ZERO(ret, "creating a fifo at path %s", filepath);
	} else {
		T_ASSERT_FAIL("stat operation on %s", filepath);
	}
}

void
kevent_one_shot(int kq, int fd, int filter)
{
	int retval             = 0;
	struct timespec t_zero = {0, 0};
	struct kevent kev[1];

	T_QUIET;
	T_ASSERT_GE(kq, 0, "ensure kq is valid");
	T_LOG("kevent doing ONESHOT %s", filter == EVFILT_READ ? "read" : "write");

	EV_SET(kev, fd, filter, EV_ADD | EV_ONESHOT, 0, 0, NULL);
	retval = kevent(kq, kev, 1, NULL, 0, &t_zero);
	T_QUIET;
	T_ASSERT_POSIX_ZERO(retval, "ONESHOT kevent for fd %d, filter %d", fd, filter);
}

T_DECL(kqueue_fifo_18776047, "Tests kqueue, kevent for watching a fifo.", T_META_LTEPHASE(LTE_POSTINIT))
{
	struct kevent kev[1];
	int read_fd, write_fd, kq;
	int retval         = 0;
	int iter           = 0;
	const char * fpath = TMP_FILE_PATH;
	T_SETUPBEGIN;
	create_fifo(fpath);

	kq = kqueue();
	T_ASSERT_GE(kq, 0, "create a kqueue");

	read_fd = open(fpath, O_RDONLY | O_APPEND | O_NONBLOCK);
	T_ASSERT_POSIX_SUCCESS(read_fd, "opening read fd on fifo.");

	write_fd = open(fpath, O_WRONLY | O_APPEND | O_NONBLOCK);
	T_ASSERT_POSIX_SUCCESS(write_fd, "opening write fd on fifo.");

	T_SETUPEND;

	kevent_one_shot(kq, write_fd, EVFILT_WRITE);
	kevent_one_shot(kq, read_fd, EVFILT_READ);

	while (iter++ < TOTAL_ITERATIONS) {
		retval = kevent(kq, NULL, 0, kev, 1, NULL);
		T_QUIET;
		T_ASSERT_GE(retval, 0, "kevent on kq %d", kq);

		if (kev[0].ident == (uintptr_t)write_fd) {
			retval = write_some_data(write_fd);
			T_LOG("writer ready iter: %d wrote %d bytes", iter, retval);
			kevent_one_shot(kq, write_fd, EVFILT_WRITE);
		} else if (kev[0].ident == (uintptr_t)read_fd) {
			retval = read_data(read_fd);
			T_LOG("reader ready iter: %d read %d bytes", iter, retval);
			kevent_one_shot(kq, read_fd, EVFILT_READ);
		}
	}
	T_PASS("kqueue_fifo_18776047 PASSED");
}
